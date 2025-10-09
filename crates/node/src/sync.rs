#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::Arc;

use p2p::{InvType, Inventory};
use parking_lot::Mutex;

/// Minimal header/chain sync manager used during the MVP phase.
///
/// The manager tracks which block hashes are already known so that we can
/// filter incoming inventory announcements and request only relevant data.
#[derive(Default, Clone)]
pub struct SyncManager {
    known_blocks: Arc<Mutex<HashSet<[u8; 32]>>>,
}

impl SyncManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_known(&self, hash: [u8; 32]) {
        self.known_blocks.lock().insert(hash);
    }

    pub fn filter_inventory(&self, inventory: &Inventory) -> Inventory {
        let mut unknown = Vec::new();
        let mut guard = self.known_blocks.lock();
        for item in &inventory.items {
            if item.kind == InvType::Block && guard.contains(&item.hash) {
                continue;
            }
            unknown.push(item.clone());
            if item.kind == InvType::Block {
                guard.insert(item.hash);
            }
        }
        Inventory { items: unknown }
    }
}
