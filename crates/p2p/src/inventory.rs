use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::types::InventoryItem;

/// Tracks recently seen inventory hashes to avoid redundant gossip.
#[derive(Debug)]
pub struct InventoryRegistry {
    ttl: Duration,
    inner: Mutex<HashMap<InventoryItem, Instant>>,
}

impl InventoryRegistry {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register items and return the subset that were not seen recently.
    pub fn filter_new(&self, items: &[InventoryItem]) -> Vec<InventoryItem> {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        guard.retain(|_, seen| now.duration_since(*seen) <= self.ttl);
        let mut fresh = Vec::new();
        for item in items {
            match guard.get_mut(item) {
                Some(seen) => {
                    *seen = now;
                }
                None => {
                    guard.insert(item.clone(), now);
                    fresh.push(item.clone());
                }
            }
        }
        fresh
    }
}

impl Default for InventoryRegistry {
    fn default() -> Self {
        Self::new(Duration::from_secs(5 * 60))
    }
}
