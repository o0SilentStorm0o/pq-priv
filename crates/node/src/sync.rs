use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use consensus::{Block, BlockHeader, pow_hash};
use p2p::{InvType, Inventory};
use parking_lot::Mutex;

use crate::state::{ChainError, ChainState};

struct OrphanBlock {
    block: Block,
    received_at: Instant,
}

struct SyncState {
    known: HashSet<[u8; 32]>,
    pending: HashSet<[u8; 32]>,
    orphans: HashMap<[u8; 32], OrphanBlock>,
    children: HashMap<[u8; 32], Vec<[u8; 32]>>,
}

impl SyncState {
    fn new() -> Self {
        Self {
            known: HashSet::new(),
            pending: HashSet::new(),
            orphans: HashMap::new(),
            children: HashMap::new(),
        }
    }
}

/// Coordinates block download and orphan promotion.
pub struct SyncManager {
    state: Mutex<SyncState>,
    orphan_limit: usize,
    orphan_ttl: Duration,
}

impl SyncManager {
    pub fn new(orphan_limit: usize, orphan_ttl: Duration) -> Self {
        Self {
            state: Mutex::new(SyncState::new()),
            orphan_limit,
            orphan_ttl,
        }
    }

    pub fn mark_known(&self, hash: [u8; 32]) {
        self.state.lock().known.insert(hash);
    }

    pub fn register_headers(&self, headers: &[BlockHeader], chain: &ChainState) -> Vec<[u8; 32]> {
        let mut guard = self.state.lock();
        purge_expired_orphans(&mut guard, self.orphan_ttl);
        let mut requests = Vec::new();
        for header in headers {
            let hash = pow_hash(header);
            if chain.has_block(&hash) {
                guard.pending.remove(&hash);
                guard.known.insert(hash);
                continue;
            }
            if guard.pending.insert(hash) {
                requests.push(hash);
            }
        }
        requests
    }

    pub fn filter_inventory(&self, inventory: &Inventory) -> Inventory {
        let mut guard = self.state.lock();
        purge_expired_orphans(&mut guard, self.orphan_ttl);
        let mut fresh = Vec::new();
        for item in &inventory.items {
            match item.kind {
                InvType::Block => {
                    if !guard.known.contains(&item.hash) && !guard.pending.contains(&item.hash) {
                        guard.pending.insert(item.hash);
                        fresh.push(item.clone());
                    }
                }
                _ => fresh.push(item.clone()),
            }
        }
        Inventory { items: fresh }
    }

    pub fn process_block(
        &self,
        block: Block,
        chain: &mut ChainState,
    ) -> Result<Vec<[u8; 32]>, ChainError> {
        let hash = pow_hash(&block.header);
        {
            let mut state = self.state.lock();
            purge_expired_orphans(&mut state, self.orphan_ttl);
            if state.known.contains(&hash) {
                state.pending.remove(&hash);
                return Ok(Vec::new());
            }
        }

        let mut to_connect = VecDeque::new();
        let mut applied = Vec::new();
        to_connect.push_back(block);

        while let Some(next_block) = to_connect.pop_front() {
            let hash = pow_hash(&next_block.header);
            let parent = next_block.header.prev_hash;
            {
                let mut state = self.state.lock();
                state.pending.remove(&hash);
                if !parent_known(&state, chain, &parent) {
                    insert_orphan(
                        &mut state,
                        self.orphan_limit,
                        OrphanBlock {
                            block: next_block,
                            received_at: Instant::now(),
                        },
                    );
                    continue;
                }
                state.known.insert(hash);
                let children = state.children.remove(&hash).unwrap_or_default();
                let mut promoted = Vec::new();
                for child_hash in children {
                    if let Some(child) = state.orphans.remove(&child_hash) {
                        promoted.push(child.block);
                    }
                }
                drop(state);

                chain.apply_block(next_block.clone())?;
                applied.push(hash);
                for child in promoted {
                    to_connect.push_back(child);
                }
            }
        }

        Ok(applied)
    }

    #[cfg(test)]
    pub fn orphan_count(&self) -> usize {
        self.state.lock().orphans.len()
    }
}

fn detach_child(
    children: &mut HashMap<[u8; 32], Vec<[u8; 32]>>,
    parent: [u8; 32],
    child: [u8; 32],
) {
    if let Some(entries) = children.get_mut(&parent) {
        entries.retain(|hash| *hash != child);
        if entries.is_empty() {
            children.remove(&parent);
        }
    }
}

fn purge_expired_orphans(state: &mut SyncState, ttl: Duration) {
    let now = Instant::now();
    let mut expired = Vec::new();
    for (hash, orphan) in state.orphans.iter() {
        if now.duration_since(orphan.received_at) > ttl {
            expired.push(*hash);
        }
    }
    for hash in expired {
        if let Some(orphan) = state.orphans.remove(&hash) {
            detach_child(&mut state.children, orphan.block.header.prev_hash, hash);
        }
    }
}

fn insert_orphan(state: &mut SyncState, limit: usize, orphan: OrphanBlock) {
    let hash = pow_hash(&orphan.block.header);
    if state.orphans.len() >= limit
        && let Some((old_hash, old)) = state
            .orphans
            .iter()
            .min_by_key(|(_, block)| block.received_at)
            .map(|(hash, _)| *hash)
            .and_then(|hash| state.orphans.remove(&hash).map(|old| (hash, old)))
    {
        detach_child(&mut state.children, old.block.header.prev_hash, old_hash);
    }
    state
        .children
        .entry(orphan.block.header.prev_hash)
        .or_default()
        .push(hash);
    state.orphans.insert(hash, orphan);
}

fn parent_known(state: &SyncState, chain: &ChainState, parent: &[u8; 32]) -> bool {
    if *parent == [0u8; 32] {
        return true;
    }
    state.known.contains(parent) || chain.has_block(parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{Block, BlockHeader, ChainParams, merkle_root};
    use crypto::KeyMaterial;
    use p2p::Inventory;
    use pow::mine_block;
    use std::thread;
    use storage::Store;
    use tempfile::tempdir;
    use tx::{Output, OutputMeta, TxBuilder, Witness, build_stealth_blob};

    fn build_block(prev_hash: [u8; 32], time: u64, n_bits: u32, params: &ChainParams) -> Block {
        let tx = coinbase(time);
        let txs = vec![tx.clone()];
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: merkle_root(&txs),
            utxo_root: [0u8; 32],
            time,
            n_bits,
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
            .set_witness(Witness::new(Vec::new(), seed, Vec::new()))
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
            merkle_root: merkle_root(&txs),
            utxo_root: [0u8; 32],
            time,
            n_bits,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, txs, &params.pow_limit)
    }

    #[test]
    fn register_headers_marks_unknown_blocks_for_download() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, 0x207fffff, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis.clone()).unwrap();
        let manager = SyncManager::new(8, Duration::from_secs(60));
        manager.mark_known(pow_hash(&genesis.header));

        let next = mine_child_block(&chain, &params, 1_000);
        let header = next.header.clone();
        let hash = pow_hash(&header);

        assert!(!chain.has_block(&hash));
        let requests = manager.register_headers(std::slice::from_ref(&header), &chain);
        assert_eq!(requests, vec![hash]);

        manager.process_block(next, &mut chain).unwrap();
        let requests_after = manager.register_headers(std::slice::from_ref(&header), &chain);
        assert!(requests_after.is_empty());
    }

    #[test]
    fn stores_and_promotes_orphans() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, 0x207fffff, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis.clone()).unwrap();
        let manager = SyncManager::new(8, Duration::from_secs(60));
        manager.mark_known(pow_hash(&genesis.header));

        let parent = mine_child_block(&chain, &params, 1_000);
        let build_dir = tempdir().unwrap();
        let build_store = Store::open(build_dir.path()).unwrap();
        let mut build_chain =
            ChainState::bootstrap(params.clone(), build_store, genesis.clone()).unwrap();
        build_chain.apply_block(parent.clone()).unwrap();
        let child = mine_child_block(&build_chain, &params, 1_000 + params.target_spacing);

        assert!(
            manager
                .process_block(child.clone(), &mut chain)
                .unwrap()
                .is_empty()
        );
        assert_eq!(manager.orphan_count(), 1);

        let applied = manager.process_block(parent.clone(), &mut chain).unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(manager.orphan_count(), 0);
        assert_eq!(applied[0], pow_hash(&parent.header));
        assert_eq!(applied[1], pow_hash(&child.header));
    }

    #[test]
    fn evicts_oldest_orphan_when_limit_exceeded() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, 0x207fffff, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis.clone()).unwrap();
        let manager = SyncManager::new(1, Duration::from_secs(60));
        manager.mark_known(pow_hash(&genesis.header));

        let parent = mine_child_block(&chain, &params, 1_000);
        let build_dir = tempdir().unwrap();
        let build_store = Store::open(build_dir.path()).unwrap();
        let mut build_chain =
            ChainState::bootstrap(params.clone(), build_store, genesis.clone()).unwrap();
        build_chain.apply_block(parent.clone()).unwrap();
        let child_a = mine_child_block(&build_chain, &params, 1_000 + params.target_spacing);
        let child_b = mine_child_block(&build_chain, &params, 1_000 + params.target_spacing * 2);

        manager.process_block(child_a, &mut chain).unwrap();
        assert_eq!(manager.orphan_count(), 1);
        manager.process_block(child_b, &mut chain).unwrap();
        assert_eq!(manager.orphan_count(), 1);
    }

    #[test]
    fn prunes_orphans_after_ttl() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, 0x207fffff, &params);
        let mut chain = ChainState::bootstrap(params.clone(), store, genesis.clone()).unwrap();
        let manager = SyncManager::new(4, Duration::from_millis(5));
        manager.mark_known(pow_hash(&genesis.header));

        let parent = mine_child_block(&chain, &params, 1_000);
        let build_dir = tempdir().unwrap();
        let build_store = Store::open(build_dir.path()).unwrap();
        let mut build_chain =
            ChainState::bootstrap(params.clone(), build_store, genesis.clone()).unwrap();
        build_chain.apply_block(parent.clone()).unwrap();
        let child = mine_child_block(&build_chain, &params, 1_000 + params.target_spacing);

        manager.process_block(child, &mut chain).unwrap();
        thread::sleep(Duration::from_millis(10));
        manager.filter_inventory(&Inventory { items: Vec::new() });
        assert_eq!(manager.orphan_count(), 0);
    }
}
