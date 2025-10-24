use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Arc;
use std::time::Instant;

use codec::to_vec_cbor;
use consensus::{
    Block, BlockHeader, ChainParams, ConsensusError, block_work, next_difficulty, pow_hash,
    validate_block,
};
use hex::encode as hex_encode;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use parking_lot::Mutex;
use storage::{CheckpointManager, RocksUtxoStore, SnapshotConfig, StorageError, Store, TipInfo};
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use tx::{Tx, TxId};
use utxo::{BlockUndo, OutPoint, UtxoBackend, UtxoError, apply_block, undo_block};

use crate::mempool::{MempoolAddOutcome, TxPool};
use crate::metrics::PrivacyMetrics;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("utxo error: {0}")]
    Utxo(#[from] UtxoError),
    #[error("genesis missing transactions")]
    InvalidGenesis,
    #[error("consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("unknown parent {0:?}")]
    UnknownParent([u8; 32]),
    #[error("missing undo data for block {0:?}")]
    MissingUndo([u8; 32]),
    #[error("reorg failed: {0}")]
    ReorgFailure(String),
}

const CHAIN_EVENT_BUFFER: usize = 64;

#[derive(Clone, Debug)]
pub enum ChainEvent {
    TipUpdated {
        height: u64,
        hash: [u8; 32],
        header: BlockHeader,
    },
}

#[derive(Clone)]
struct BlockEntry {
    block: Block,
    height: u64,
    cumulative_work: BigUint,
    parent: Option<[u8; 32]>,
    active: bool,
}

impl BlockEntry {
    fn header(&self) -> &BlockHeader {
        &self.block.header
    }
}

pub struct ChainState {
    params: ChainParams,
    store: Store,
    utxo: RocksUtxoStore,
    index: HashMap<[u8; 32], BlockEntry>,
    undo_cache: HashMap<[u8; 32], BlockUndo>,
    active_chain: Vec<[u8; 32]>,
    active_tip: Option<[u8; 32]>,
    active_work: BigUint,
    reorg_count: u64,
    snapshot_config: Option<SnapshotConfig>,
    checkpoint_manager: Option<CheckpointManager>,
    last_commit_ms: f64,
    events: broadcast::Sender<ChainEvent>,
    mempool: Option<Arc<Mutex<TxPool>>>,
    privacy_metrics: Option<Arc<PrivacyMetrics>>,
}

impl ChainState {
    pub fn bootstrap(
        params: ChainParams,
        store: Store,
        genesis: Block,
    ) -> Result<Self, ChainError> {
        if genesis.txs.is_empty() {
            return Err(ChainError::InvalidGenesis);
        }
        let utxo = store.new_utxo_store();
        let (events, _) = broadcast::channel(CHAIN_EVENT_BUFFER);
        let mut state = Self {
            params,
            store,
            utxo,
            index: HashMap::new(),
            undo_cache: HashMap::new(),
            active_chain: Vec::new(),
            active_tip: None,
            active_work: BigUint::zero(),
            reorg_count: 0,
            snapshot_config: None,
            checkpoint_manager: None,
            last_commit_ms: 0.0,
            events,
            mempool: None,
            privacy_metrics: None,
        };
        state.initialize(genesis)?;
        Ok(state)
    }

    fn initialize(&mut self, genesis: Block) -> Result<(), ChainError> {
        if let Some(tip) = self.store.tip()? {
            self.reorg_count = tip.reorg_count;
            self.rebuild_from_store()?;
        } else {
            self.install_genesis(genesis)?;
        }
        Ok(())
    }

    pub fn configure_snapshots(&mut self, config: SnapshotConfig) -> Result<(), ChainError> {
        self.snapshot_config = Some(config.clone());
        self.checkpoint_manager = Some(CheckpointManager::new(self.store.clone()));
        let current_height = self.height();
        self.maybe_snapshot(current_height)?;
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.events.subscribe()
    }

    pub fn attach_mempool(&mut self, mempool: Arc<Mutex<TxPool>>) {
        self.mempool = Some(mempool);
    }

    pub fn attach_privacy_metrics(&mut self, metrics: Arc<PrivacyMetrics>) {
        self.privacy_metrics = Some(metrics);
    }

    fn install_genesis(&mut self, genesis: Block) -> Result<(), ChainError> {
        self.store.reset_utxo()?;
        let mut batch = self.store.begin_block_batch()?;
        let undo = {
            let mut backend = batch.utxo_backend();
            apply_block(&mut backend, &genesis, 0, None::<fn(&str, u64)>)?
        };
        let hash = pow_hash(&genesis.header);
        let work = block_work(genesis.header.n_bits)?;
        let tip_info = TipInfo::new(0, hash, work.clone(), 0);
        batch.stage_block(0, &genesis)?;
        batch.stage_tip(&tip_info)?;
        batch.commit()?;

        self.utxo = self.store.new_utxo_store();
        self.undo_cache.insert(hash, undo);
        self.index.insert(
            hash,
            BlockEntry {
                block: genesis,
                height: 0,
                cumulative_work: work.clone(),
                parent: None,
                active: true,
            },
        );
        self.active_chain.push(hash);
        self.active_tip = Some(hash);
        self.active_work = work;
        self.last_commit_ms = 0.0;
        self.publish_tip(hash, 0);
        Ok(())
    }

    fn rebuild_from_store(&mut self) -> Result<(), ChainError> {
        self.store.reset_utxo()?;
        self.utxo = self.store.new_utxo_store();
        self.index.clear();
        self.undo_cache.clear();
        self.active_chain.clear();
        self.active_tip = None;
        self.active_work = BigUint::zero();

        let blocks = self.store.load_blocks()?;
        for (height, block) in blocks.into_iter().enumerate() {
            let hash = pow_hash(&block.header);
            let parent = if height == 0 {
                None
            } else {
                Some(self.active_chain[height - 1])
            };
            let undo = apply_block(&mut self.utxo, &block, height as u64, None::<fn(&str, u64)>)?;
            let work = block_work(block.header.n_bits)?;
            let cumulative = if let Some(parent_hash) = parent {
                self.index
                    .get(&parent_hash)
                    .map(|entry| entry.cumulative_work.clone() + &work)
                    .unwrap_or_else(BigUint::zero)
            } else {
                work.clone()
            };
            self.undo_cache.insert(hash, undo);
            self.index.insert(
                hash,
                BlockEntry {
                    block,
                    height: height as u64,
                    cumulative_work: cumulative.clone(),
                    parent,
                    active: true,
                },
            );
            self.active_chain.push(hash);
            self.active_tip = Some(hash);
            self.active_work = cumulative;
        }
        self.last_commit_ms = 0.0;
        if let Some(tip) = self.active_tip {
            let height = self.height();
            self.publish_tip(tip, height);
        }
        Ok(())
    }

    pub fn height(&self) -> u64 {
        self.active_chain.len().saturating_sub(1) as u64
    }

    pub fn best_hash(&self) -> [u8; 32] {
        self.active_tip.unwrap_or([0u8; 32])
    }

    pub fn apply_block(&mut self, block: Block) -> Result<(), ChainError> {
        let hash = pow_hash(&block.header);
        if self.index.contains_key(&hash) {
            debug!(hash = %hex_encode(hash), "duplicate block ignored");
            return Ok(());
        }
        let parent_hash = block.header.prev_hash;
        let parent_entry = self.index.get(&parent_hash);
        let height = match parent_entry {
            Some(entry) => entry.height + 1,
            None => {
                if self.active_chain.is_empty() {
                    0
                } else {
                    return Err(ChainError::UnknownParent(parent_hash));
                }
            }
        };

        let prev_header = parent_entry.map(|entry| entry.header());
        validate_block(prev_header, &block, &self.params)?;

        let work = block_work(block.header.n_bits)?;
        let cumulative = parent_entry
            .map(|entry| entry.cumulative_work.clone() + &work)
            .unwrap_or_else(|| work.clone());

        // Determine if this block extends the active tip
        let extends_active = self.active_tip == Some(parent_hash) || self.active_chain.is_empty();

        // Only validate difficulty and timestamp for blocks extending the active chain
        // Side chain blocks are validated during reorg if they become active
        if extends_active && parent_entry.is_some() {
            let history = self.recent_headers(self.params.window);
            let expected_bits = next_difficulty(&self.params, &history)?;
            if block.header.n_bits != expected_bits {
                return Err(ChainError::Consensus(ConsensusError::InvalidBits));
            }
            let mtp = self.median_time_past();
            if block.header.time <= mtp {
                return Err(ChainError::Consensus(ConsensusError::InvalidTimestamp));
            }
        }

        if extends_active {
            self.apply_to_active(block, hash, parent_hash, height, cumulative)?;
        } else {
            self.insert_side_chain(block, hash, parent_hash, height, cumulative)?;
        }
        Ok(())
    }

    fn apply_to_active(
        &mut self,
        block: Block,
        hash: [u8; 32],
        parent_hash: [u8; 32],
        height: u64,
        cumulative: BigUint,
    ) -> Result<(), ChainError> {
        let confirmed = Self::confirmed_txids(&block);
        let mut batch = self.store.begin_block_batch()?;
        let start = Instant::now();
        let undo = {
            let mut backend = batch.utxo_backend();
            
            // Create metrics callback if privacy metrics are attached
            let metrics_fn = self.privacy_metrics.as_ref().map(|m| {
                let metrics = Arc::clone(m);
                move |event: &str, value: u64| {
                    match event {
                        "verify_success" => metrics.record_verify_success(value),
                        "invalid_proof" => metrics.record_invalid_proof(),
                        "balance_failure" => metrics.record_balance_failure(),
                        _ => {}
                    }
                }
            });
            
            apply_block(&mut backend, &block, height, metrics_fn)?
        };
        let tip_info = TipInfo::new(height, hash, cumulative.clone(), self.reorg_count);
        batch.stage_block(height, &block)?;
        batch.stage_tip(&tip_info)?;
        batch.commit()?;
        self.utxo = self.store.new_utxo_store();

        self.undo_cache.insert(hash, undo);
        self.index.insert(
            hash,
            BlockEntry {
                block,
                height,
                cumulative_work: cumulative.clone(),
                parent: if height == 0 { None } else { Some(parent_hash) },
                active: true,
            },
        );
        self.active_chain.push(hash);
        self.active_tip = Some(hash);
        self.active_work = cumulative;
        let duration_ms = start.elapsed().as_secs_f64() * 1_000.0;
        self.last_commit_ms = duration_ms;
        self.maybe_snapshot(height)?;
        debug!(
            height,
            hash = %hex_encode(hash),
            duration_ms,
            "block applied to active chain"
        );
        self.publish_tip(hash, height);
        self.remove_confirmed(&confirmed);
        Ok(())
    }

    fn insert_side_chain(
        &mut self,
        block: Block,
        hash: [u8; 32],
        parent_hash: [u8; 32],
        height: u64,
        cumulative: BigUint,
    ) -> Result<(), ChainError> {
        self.index.insert(
            hash,
            BlockEntry {
                block,
                height,
                cumulative_work: cumulative.clone(),
                parent: Some(parent_hash),
                active: false,
            },
        );
        if cumulative > self.active_work {
            self.perform_reorg(hash)?;
        }
        Ok(())
    }

    pub fn next_difficulty_bits(&self) -> Result<u32, ConsensusError> {
        if self.active_chain.is_empty() {
            return Err(ConsensusError::InvalidBits);
        }
        let history = self.recent_headers(self.params.window);
        next_difficulty(&self.params, &history)
    }

    pub fn has_utxo(&self, txid: &[u8; 32], index: u32) -> bool {
        let outpoint = OutPoint::new(*txid, index);
        self.utxo
            .get(&outpoint)
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    #[allow(dead_code)]
    pub fn utxo_count(&self) -> Result<usize, ChainError> {
        Ok(self.store.utxo_len()?)
    }

    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.index.contains_key(hash)
    }

    pub fn block_bytes(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.index
            .get(hash)
            .and_then(|entry| to_vec_cbor(&entry.block).ok())
    }

    pub fn tip(&self) -> &Block {
        let hash = self
            .active_tip
            .expect("chain must contain at least the genesis block");
        &self.index[&hash].block
    }

    #[allow(dead_code)]
    pub fn block_locator(&self) -> Vec<[u8; 32]> {
        if self.active_chain.is_empty() {
            return Vec::new();
        }
        let mut locator = Vec::new();
        let mut step = 1usize;
        let mut index = self.active_chain.len() as isize - 1;
        while index >= 0 {
            locator.push(self.active_chain[index as usize]);
            if index == 0 {
                break;
            }
            index -= step as isize;
            if locator.len() >= 10 {
                step *= 2;
            }
        }
        let genesis = self.active_chain.first().unwrap();
        if locator.last() != Some(genesis) {
            locator.push(*genesis);
        }
        locator
    }

    pub fn headers_for_locator(
        &self,
        locator: &[[u8; 32]],
        stop: Option<&[u8; 32]>,
        limit: usize,
    ) -> Vec<BlockHeader> {
        let mut start_height = 0usize;
        for hash in locator {
            if let Some(entry) = self.index.get(hash).filter(|entry| entry.active) {
                start_height = entry.height as usize + 1;
                break;
            }
        }
        let mut headers = Vec::new();
        for hash in self.active_chain.iter().skip(start_height) {
            if stop.is_some_and(|stop_hash| hash == stop_hash) {
                break;
            }
            headers.push(self.index[hash].header().clone());
            if headers.len() >= limit {
                break;
            }
        }
        headers
    }

    fn recent_headers(&self, limit: usize) -> Vec<BlockHeader> {
        if self.active_chain.is_empty() {
            return Vec::new();
        }
        let len = self.active_chain.len();
        let start = len.saturating_sub(limit);
        self.active_chain[start..]
            .iter()
            .map(|hash| self.index[hash].header().clone())
            .collect()
    }

    fn median_time_past(&self) -> u64 {
        let mut times: Vec<u64> = self
            .active_chain
            .iter()
            .rev()
            .take(11)
            .map(|hash| self.index[hash].header().time)
            .collect();
        if times.is_empty() {
            return 0;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    fn maybe_snapshot(&mut self, height: u64) -> Result<(), ChainError> {
        let config = match self.snapshot_config.as_ref() {
            Some(cfg) => cfg,
            None => return Ok(()),
        };
        let manager = match self.checkpoint_manager.as_ref() {
            Some(mgr) => mgr,
            None => return Ok(()),
        };
        if let Some(path) = manager
            .maybe_snapshot(config, height)
            .map_err(ChainError::from)?
        {
            let size = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            info!(
                height,
                path = %path.display(),
                size_bytes = size,
                "checkpoint created"
            );
        }
        Ok(())
    }

    fn publish_tip(&self, hash: [u8; 32], height: u64) {
        if let Some(entry) = self.index.get(&hash) {
            let _ = self.events.send(ChainEvent::TipUpdated {
                height,
                hash,
                header: entry.header().clone(),
            });
        }
    }

    fn confirmed_txids(block: &Block) -> Vec<TxId> {
        block.txs.iter().skip(1).map(|tx| tx.txid()).collect()
    }

    fn remove_confirmed(&self, txids: &[TxId]) {
        if txids.is_empty() {
            return;
        }
        if let Some(pool) = &self.mempool {
            pool.lock().remove_confirmed(txids);
        }
    }

    fn collect_confirmed_txids(&self, hashes: &[[u8; 32]]) -> Vec<TxId> {
        let mut txids = Vec::new();
        for hash in hashes {
            if let Some(entry) = self.index.get(hash) {
                txids.extend(entry.block.txs.iter().skip(1).map(|tx| tx.txid()));
            }
        }
        txids
    }

    fn collect_detached_transactions(&self, hashes: &[[u8; 32]]) -> Vec<Tx> {
        let mut txs = Vec::new();
        for hash in hashes.iter().rev() {
            if let Some(entry) = self.index.get(hash) {
                txs.extend(entry.block.txs.iter().skip(1).cloned());
            }
        }
        txs
    }

    fn reintroduce_transactions(&self, txs: Vec<Tx>, skip: &HashSet<TxId>) {
        let Some(pool) = &self.mempool else {
            return;
        };
        for tx in txs {
            let txid = tx.txid();
            if skip.contains(&txid) {
                continue;
            }
            let outcome = pool
                .lock()
                .accept_transaction(tx, None, |txid, index| self.has_utxo(txid, index));
            match outcome {
                MempoolAddOutcome::Accepted { txid } => {
                    debug!(%txid, "reintroduced transaction after reorg");
                }
                MempoolAddOutcome::Duplicate => {}
                MempoolAddOutcome::StoredOrphan { missing } => {
                    debug!(txid = %txid, missing = missing.len(), "reintroduced transaction stored as orphan after reorg");
                }
                MempoolAddOutcome::Rejected(reason) => {
                    warn!(%txid, ?reason, "failed to reintroduce transaction after reorg");
                }
            }
        }
    }

    fn perform_reorg(&mut self, new_tip: [u8; 32]) -> Result<(), ChainError> {
        let old_tip = self
            .active_tip
            .ok_or_else(|| ChainError::ReorgFailure("no active tip".into()))?;
        if old_tip == new_tip {
            return Ok(());
        }

        let mut ancestors = HashSet::new();
        let mut cursor = Some(new_tip);
        while let Some(hash) = cursor {
            ancestors.insert(hash);
            cursor = self.index.get(&hash).and_then(|entry| entry.parent);
        }

        let mut detach = Vec::new();
        let mut lca = None;
        cursor = self.active_tip;
        while let Some(hash) = cursor {
            if ancestors.contains(&hash) {
                lca = Some(hash);
                break;
            }
            detach.push(hash);
            cursor = self.index.get(&hash).and_then(|entry| entry.parent);
        }
        let lca = lca.ok_or_else(|| ChainError::ReorgFailure("no common ancestor".into()))?;

        let mut attach = Vec::new();
        cursor = Some(new_tip);
        while let Some(hash) = cursor {
            if hash == lca {
                break;
            }
            attach.push(hash);
            cursor = self.index.get(&hash).and_then(|entry| entry.parent);
        }
        attach.reverse();

        let mempool_payload = if self.mempool.is_some() {
            Some((
                self.collect_confirmed_txids(&attach),
                self.collect_detached_transactions(&detach),
            ))
        } else {
            None
        };

        let mut batch = self.store.begin_block_batch()?;
        let start = Instant::now();
        {
            let mut backend = batch.utxo_backend();
            for hash in &detach {
                let entry = self
                    .index
                    .get(hash)
                    .ok_or_else(|| ChainError::ReorgFailure("missing detach entry".into()))?;
                let undo = self
                    .undo_cache
                    .remove(hash)
                    .ok_or(ChainError::MissingUndo(*hash))?;
                undo_block(&mut backend, &entry.block, &undo)?;
                if let Some(entry) = self.index.get_mut(hash) {
                    entry.active = false;
                }
            }
            for hash in &attach {
                let entry = self
                    .index
                    .get(hash)
                    .ok_or_else(|| ChainError::ReorgFailure("missing attach entry".into()))?;
                
                // Create metrics callback if privacy metrics are attached
                let metrics_fn = self.privacy_metrics.as_ref().map(|m| {
                    let metrics = Arc::clone(m);
                    move |event: &str, value: u64| {
                        match event {
                            "verify_success" => metrics.record_verify_success(value),
                            "invalid_proof" => metrics.record_invalid_proof(),
                            "balance_failure" => metrics.record_balance_failure(),
                            _ => {}
                        }
                    }
                });
                
                let undo = apply_block(&mut backend, &entry.block, entry.height, metrics_fn)?;
                self.undo_cache.insert(*hash, undo);
                if let Some(entry) = self.index.get_mut(hash) {
                    entry.active = true;
                }
            }
        }

        let lca_height = self.index.get(&lca).unwrap().height;
        self.active_chain.truncate((lca_height + 1) as usize);
        for hash in &attach {
            self.active_chain.push(*hash);
        }

        let tip_hash = *self
            .active_chain
            .last()
            .ok_or_else(|| ChainError::ReorgFailure("empty active chain".into()))?;
        let tip_entry = self
            .index
            .get(&tip_hash)
            .ok_or_else(|| ChainError::ReorgFailure("missing tip entry".into()))?;
        let tip_height = tip_entry.height;
        let tip_work = tip_entry.cumulative_work.clone();
        self.active_tip = Some(tip_hash);
        self.active_work = tip_work.clone();
        self.reorg_count = self.reorg_count.saturating_add(1);

        for hash in &attach {
            let entry = self.index.get(hash).unwrap();
            batch.stage_block(entry.height, &entry.block)?;
        }
        let tip_info = TipInfo::new(tip_height, tip_hash, tip_work.clone(), self.reorg_count);
        batch.stage_tip(&tip_info)?;
        batch.commit()?;
        self.utxo = self.store.new_utxo_store();

        let duration_ms = start.elapsed().as_secs_f64() * 1_000.0;
        self.last_commit_ms = duration_ms;
        self.maybe_snapshot(tip_height)?;
        let from_height = self.index.get(&old_tip).map(|e| e.height).unwrap_or(0);
        info!(
            from_height,
            to_height = tip_height,
            from_hash = %hex_encode(old_tip),
            to_hash = %hex_encode(tip_hash),
            duration_ms,
            "chain reorg"
        );
        self.publish_tip(tip_hash, tip_height);
        if let Some((attach_txids, detached_txs)) = mempool_payload {
            if !attach_txids.is_empty() {
                self.remove_confirmed(&attach_txids);
            }
            let mut skip = HashSet::with_capacity(attach_txids.len());
            for txid in &attach_txids {
                skip.insert(*txid);
            }
            self.reintroduce_transactions(detached_txs, &skip);
        }
        Ok(())
    }

    pub fn metrics(&self) -> ChainMetrics {
        let height = self.height();
        let (current_target, work) = match self.active_tip.and_then(|hash| self.index.get(&hash)) {
            Some(entry) => (entry.header().n_bits, entry.cumulative_work.clone()),
            None => (0, BigUint::zero()),
        };
        ChainMetrics {
            height,
            cumulative_work: work,
            current_target,
            reorg_count: self.reorg_count,
            last_commit_ms: self.last_commit_ms,
        }
    }

    pub fn db_stats(&self) -> ChainDbStats {
        let running = self.store.running_compactions().unwrap_or(0);
        ChainDbStats {
            running_compactions: running,
        }
    }

    /// Returns a reference to the underlying RocksDB store for metrics collection
    pub fn store(&self) -> &Store {
        &self.store
    }
}

pub struct ChainMetrics {
    pub height: u64,
    pub cumulative_work: BigUint,
    pub current_target: u32,
    pub reorg_count: u64,
    pub last_commit_ms: f64,
}

impl ChainMetrics {
    pub fn cumulative_work_f64(&self) -> f64 {
        self.cumulative_work.to_f64().unwrap_or(f64::MAX)
    }
}

pub struct ChainDbStats {
    pub running_compactions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::BlockHeader;
    use crypto::KeyMaterial;
    use pow::mine_block;
    use std::sync::Arc;
    use storage::Store;
    use tempfile::tempdir;
    use tx::{
        Output, OutputMeta, TxBuilder, Witness, binding_hash, build_signed_input,
        build_stealth_blob,
    };

    use crate::mempool::{MempoolAddOutcome, TxPool, TxPoolConfig};

    #[test]
    fn rejects_block_with_wrong_prev_hash() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");

        let bogus_prev = [9u8; 32];
        let forged = build_block(bogus_prev, 1, &params);

        let err = chain
            .apply_block(forged)
            .expect_err("should reject forged block");
        match err {
            ChainError::Consensus(ConsensusError::InvalidParent) => {}
            ChainError::UnknownParent(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn block_locator_contains_tip_and_genesis() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
        for i in 1..=6u64 {
            let block = mine_child_block(&chain, &params, 1_000 + i * params.target_spacing);
            chain.apply_block(block).expect("apply block");
        }
        let locator = chain.block_locator();
        assert_eq!(locator.first(), Some(&pow_hash(&chain.tip().header)));
        assert_eq!(
            locator.last(),
            Some(&pow_hash(chain.index[&chain.active_chain[0]].header()))
        );
    }

    #[test]
    fn headers_for_locator_returns_expected_sequence() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
        for i in 1..=4u64 {
            let block = mine_child_block(&chain, &params, 1_000 + i * params.target_spacing);
            chain.apply_block(block).expect("apply block");
        }
        let locator = vec![pow_hash(chain.index[&chain.active_chain[2]].header())];
        let headers = chain.headers_for_locator(&locator, None, 10);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            chain.index[&chain.active_chain[3]].header().clone()
        );
        assert_eq!(
            headers[1],
            chain.index[&chain.active_chain[4]].header().clone()
        );
    }

    #[test]
    fn rejects_block_with_wrong_difficulty() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
        let good = mine_child_block(&chain, &params, 1_000 + params.target_spacing);
        chain.apply_block(good.clone()).expect("apply good block");

        // Create forged block that extends active tip but with wrong difficulty
        let tx = coinbase(good.header.time + params.target_spacing);
        let txs = vec![tx.clone()];
        let bad_bits = chain.next_difficulty_bits().unwrap().saturating_sub(1);
        let header = BlockHeader {
            version: 1,
            prev_hash: pow_hash(&good.header),
            merkle_root: consensus::merkle_root(&txs),
            utxo_root: [0u8; 32],
            time: good.header.time + params.target_spacing,
            n_bits: bad_bits,
            nonce: 0,
            alg_tag: 1,
        };
        let forged = mine_block(header, txs, &params.pow_limit);

        let err = chain.apply_block(forged).expect_err("should reject");
        match err {
            ChainError::Consensus(ConsensusError::InvalidBits) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_block_with_stale_timestamp() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
        let valid = mine_child_block(&chain, &params, 1_000 + params.target_spacing);
        chain.apply_block(valid).expect("apply block");
        let mut stale = mine_child_block(&chain, &params, chain.tip().header.time);
        stale.header.time = chain.tip().header.time;
        let err = chain
            .apply_block(stale)
            .expect_err("should reject stale timestamp");
        match err {
            ChainError::Consensus(ConsensusError::InvalidTimestamp) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn persists_chain_across_restart() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            let genesis = build_block([0u8; 32], 0, &params);
            let mut chain =
                ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
            let block = mine_child_block(&chain, &params, 2_000);
            chain.apply_block(block).expect("apply block");
            assert_eq!(chain.height(), 1);
        }
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn emits_tip_update_events() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
        let mut rx = chain.subscribe();
        let block = mine_child_block(&chain, &params, 2_000);
        chain.apply_block(block.clone()).expect("apply block");
        match rx.try_recv() {
            Ok(ChainEvent::TipUpdated {
                height,
                hash,
                header,
            }) => {
                assert_eq!(height, 1);
                assert_eq!(hash, pow_hash(&block.header));
                assert_eq!(header, block.header);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn removes_confirmed_transactions_from_mempool() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");

        let mempool = Arc::new(Mutex::new(TxPool::new(TxPoolConfig::default())));
        chain.attach_mempool(Arc::clone(&mempool));

        let base_time = 1_000 + params.target_spacing;
        let coin_material = KeyMaterial::random();
        let coin_spend = coin_material.derive_spend_keypair(0);
        let block1 = mine_active_block(
            &chain,
            &params,
            vec![coinbase_with_material(&coin_material, base_time)],
            base_time,
        );
        let coinbase_txid = block1.txs[0].txid();
        chain.apply_block(block1).expect("apply block 1");

        let spend_output = Output::new(vec![5, 6, 7], 9, OutputMeta::default());
        let witness = Witness {
            range_proofs: Vec::new(),
            stamp: base_time + 1,
            extra: (5_000u64).to_le_bytes().to_vec(),
        };
        let binding = binding_hash(std::slice::from_ref(&spend_output), &witness);
        let spend_input = build_signed_input(
            *coinbase_txid.as_bytes(),
            0,
            &coin_spend,
            vec![1, 2, 3],
            &binding,
        );
        let spend_tx = TxBuilder::new()
            .add_input(spend_input)
            .add_output(spend_output)
            .set_witness(witness)
            .build();

        let outcome = mempool
            .lock()
            .accept_transaction(spend_tx.clone(), None, |txid, index| {
                chain.has_utxo(txid, index)
            });
        assert!(matches!(outcome, MempoolAddOutcome::Accepted { .. }));
        assert!(mempool.lock().contains(&spend_tx.txid()));

        let next_material = KeyMaterial::random();
        let coinbase2 = coinbase_with_material(&next_material, base_time + params.target_spacing);
        let block2_time = chain.tip().header.time + params.target_spacing;
        let block2 = mine_active_block(
            &chain,
            &params,
            vec![coinbase2, spend_tx.clone()],
            block2_time,
        );
        chain.apply_block(block2).expect("apply block 2");

        assert!(!mempool.lock().contains(&spend_tx.txid()));
    }

    #[test]
    fn reintroduces_reorged_transactions_in_dependency_order() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");

        let mempool = Arc::new(Mutex::new(TxPool::new(TxPoolConfig::default())));
        chain.attach_mempool(Arc::clone(&mempool));

        let base_time = 2_000 + params.target_spacing;
        let coin_material = KeyMaterial::random();
        let coin_spend = coin_material.derive_spend_keypair(0);
        let block1 = mine_active_block(
            &chain,
            &params,
            vec![coinbase_with_material(&coin_material, base_time)],
            base_time,
        );
        chain.apply_block(block1.clone()).expect("apply block 1");

        let parent_material = KeyMaterial::random();
        let parent_spend = parent_material.derive_spend_keypair(0);
        let parent_output = Output::new(
            build_stealth_blob(
                &parent_material.derive_scan_keypair(0).public,
                &parent_spend.public,
                b"parent",
            ),
            25,
            OutputMeta::default(),
        );
        let parent_witness = Witness {
            range_proofs: Vec::new(),
            stamp: base_time + 1,
            extra: (6_000u64).to_le_bytes().to_vec(),
        };
        let parent_binding = binding_hash(std::slice::from_ref(&parent_output), &parent_witness);
        let parent_input = build_signed_input(
            *block1.txs[0].txid().as_bytes(),
            0,
            &coin_spend,
            vec![4, 5],
            &parent_binding,
        );
        let parent_tx = TxBuilder::new()
            .add_input(parent_input)
            .add_output(parent_output.clone())
            .set_witness(parent_witness)
            .build();

        let coinbase2_material = KeyMaterial::random();
        let coinbase2 =
            coinbase_with_material(&coinbase2_material, base_time + params.target_spacing);
        let block2_time = chain.tip().header.time + params.target_spacing;
        let block2 = mine_active_block(
            &chain,
            &params,
            vec![coinbase2.clone(), parent_tx.clone()],
            block2_time,
        );
        chain.apply_block(block2).expect("apply block 2");

        let child_material = KeyMaterial::random();
        let child_spend = child_material.derive_spend_keypair(0);
        let child_output = Output::new(
            build_stealth_blob(
                &child_material.derive_scan_keypair(0).public,
                &child_spend.public,
                b"child",
            ),
            10,
            OutputMeta::default(),
        );
        let child_witness = Witness {
            range_proofs: Vec::new(),
            stamp: base_time + 2,
            extra: (4_000u64).to_le_bytes().to_vec(),
        };
        let child_binding = binding_hash(std::slice::from_ref(&child_output), &child_witness);
        let child_input = build_signed_input(
            *parent_tx.txid().as_bytes(),
            0,
            &parent_spend,
            vec![6, 7],
            &child_binding,
        );
        let child_tx = TxBuilder::new()
            .add_input(child_input)
            .add_output(child_output)
            .set_witness(child_witness)
            .build();

        let coinbase3_material = KeyMaterial::random();
        let coinbase3 =
            coinbase_with_material(&coinbase3_material, base_time + 2 * params.target_spacing);
        let block3_time = chain.tip().header.time + params.target_spacing;
        let block3 = mine_active_block(
            &chain,
            &params,
            vec![coinbase3.clone(), child_tx.clone()],
            block3_time,
        );
        let n_bits = block3.header.n_bits;
        chain.apply_block(block3).expect("apply block 3");

        let alt_time2 = block3_time + 10;
        let alt_coinbase2 = coinbase_with_material(&KeyMaterial::random(), alt_time2);
        let block2_alt = mine_block_from(&block1, &params, n_bits, alt_time2, vec![alt_coinbase2]);
        chain
            .apply_block(block2_alt.clone())
            .expect("apply alt block 2");

        let alt_time3 = alt_time2 + params.target_spacing;
        let alt_coinbase3 = coinbase_with_material(&KeyMaterial::random(), alt_time3);
        let block3_alt =
            mine_block_from(&block2_alt, &params, n_bits, alt_time3, vec![alt_coinbase3]);
        chain
            .apply_block(block3_alt.clone())
            .expect("apply alt block 3");

        let alt_time4 = alt_time3 + params.target_spacing;
        let alt_coinbase4 = coinbase_with_material(&KeyMaterial::random(), alt_time4);
        let block4_alt =
            mine_block_from(&block3_alt, &params, n_bits, alt_time4, vec![alt_coinbase4]);
        chain.apply_block(block4_alt).expect("apply alt block 4");

        assert!(mempool.lock().contains(&parent_tx.txid()));
        assert!(mempool.lock().contains(&child_tx.txid()));
        let stats = mempool.lock().stats();
        assert_eq!(stats.tx_count, 2);
        assert_eq!(stats.orphan_count, 0);
    }

    fn build_block(prev_hash: [u8; 32], seed: u64, params: &ChainParams) -> Block {
        let tx = coinbase(seed);
        let txs = vec![tx.clone()];
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: consensus::merkle_root(&txs),
            utxo_root: [0u8; 32],
            time: seed,
            n_bits: 0x207fffff,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, txs, &params.pow_limit)
    }

    fn coinbase(seed: u64) -> tx::Tx {
        let material = KeyMaterial::random();
        let scan = material.derive_scan_keypair(0);
        let spend = material.derive_spend_keypair(0);
        let stealth = build_stealth_blob(&scan.public, &spend.public, &seed.to_le_bytes());
        TxBuilder::new()
            .add_output(Output::new(
                stealth,
                50,
                OutputMeta {
                    deposit_flag: false,
                    deposit_id: None,
                },
            ))
            .set_witness(Witness {
                range_proofs: Vec::new(),
                stamp: seed,
                extra: Vec::new(),
            })
            .build()
    }

    fn mine_child_block(chain: &ChainState, params: &ChainParams, time: u64) -> Block {
        let prev = chain.tip();
        let n_bits = chain.next_difficulty_bits().unwrap_or(prev.header.n_bits);
        let tx = coinbase(time);
        let txs = vec![tx.clone()];
        let header = BlockHeader {
            version: 1,
            prev_hash: pow_hash(&prev.header),
            merkle_root: consensus::merkle_root(&txs),
            utxo_root: [0u8; 32],
            time,
            n_bits,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, txs, &params.pow_limit)
    }

    fn coinbase_with_material(material: &KeyMaterial, stamp: u64) -> tx::Tx {
        let scan = material.derive_scan_keypair(0);
        let spend = material.derive_spend_keypair(0);
        let stealth = build_stealth_blob(&scan.public, &spend.public, &stamp.to_le_bytes());
        TxBuilder::new()
            .add_output(Output::new(stealth, 50, OutputMeta::default()))
            .set_witness(Witness {
                range_proofs: Vec::new(),
                stamp,
                extra: Vec::new(),
            })
            .build()
    }

    fn mine_active_block(
        chain: &ChainState,
        params: &ChainParams,
        txs: Vec<tx::Tx>,
        time: u64,
    ) -> Block {
        let prev = chain.tip();
        let n_bits = chain.next_difficulty_bits().unwrap_or(prev.header.n_bits);
        mine_block_from(prev, params, n_bits, time, txs)
    }

    fn mine_block_from(
        prev: &Block,
        params: &ChainParams,
        n_bits: u32,
        time: u64,
        txs: Vec<tx::Tx>,
    ) -> Block {
        let header = BlockHeader {
            version: 1,
            prev_hash: pow_hash(&prev.header),
            merkle_root: consensus::merkle_root(&txs),
            utxo_root: [0u8; 32],
            time,
            n_bits,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, txs, &params.pow_limit)
    }
}
