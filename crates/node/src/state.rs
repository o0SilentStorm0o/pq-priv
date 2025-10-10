use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::Instant;

use codec::to_vec_cbor;
use consensus::{
    Block, BlockHeader, ChainParams, ConsensusError, block_work, next_difficulty, pow_hash,
    validate_block,
};
use hex::encode as hex_encode;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use storage::{CheckpointManager, RocksUtxoStore, SnapshotConfig, StorageError, Store, TipInfo};
use thiserror::Error;
use tracing::{debug, info};
use utxo::{BlockUndo, OutPoint, UtxoBackend, UtxoError, apply_block, undo_block};

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

    fn install_genesis(&mut self, genesis: Block) -> Result<(), ChainError> {
        self.store.reset_utxo()?;
        let mut batch = self.store.begin_block_batch()?;
        let undo = {
            let mut backend = batch.utxo_backend();
            apply_block(&mut backend, &genesis, 0)?
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
                Some(self.active_chain[(height - 1) as usize])
            };
            let undo = apply_block(&mut self.utxo, &block, height as u64)?;
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

        if parent_entry.is_some() {
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

        let work = block_work(block.header.n_bits)?;
        let cumulative = parent_entry
            .map(|entry| entry.cumulative_work.clone() + &work)
            .unwrap_or_else(|| work.clone());

        if self.active_tip == Some(parent_hash) || self.active_chain.is_empty() {
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
        let mut batch = self.store.begin_block_batch()?;
        let start = Instant::now();
        let undo = {
            let mut backend = batch.utxo_backend();
            apply_block(&mut backend, &block, height)?
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
            if let Some(entry) = self.index.get(hash) {
                if entry.active {
                    start_height = entry.height as usize + 1;
                    break;
                }
            }
        }
        let mut headers = Vec::new();
        for hash in self.active_chain.iter().skip(start_height) {
            if let Some(stop_hash) = stop {
                if hash == stop_hash {
                    break;
                }
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
                let undo = apply_block(&mut backend, &entry.block, entry.height)?;
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
        self.cumulative_work.to_f64().unwrap_or(std::f64::MAX)
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
    use storage::Store;
    use tempfile::tempdir;
    use tx::{Output, OutputMeta, TxBuilder, Witness, build_stealth_blob};

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
            Some(&pow_hash(&chain.index[&chain.active_chain[0]].header()))
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
        let locator = vec![pow_hash(&chain.index[&chain.active_chain[2]].header())];
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

        let mut header = good.header.clone();
        let bad_bits = header.n_bits.saturating_sub(1);
        header.n_bits = bad_bits;
        let forged = mine_block(header, good.txs.clone(), &params.pow_limit);
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
        let commitment = crypto::commitment(50, &seed.to_le_bytes());
        TxBuilder::new()
            .add_output(Output::new(
                stealth,
                commitment,
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
}
