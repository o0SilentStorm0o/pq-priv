use std::collections::{HashMap, HashSet};

use parking_lot::Mutex;
use tx::{Input, Tx, TxId};
use utxo::OutPoint;

use codec::to_vec_cbor;

#[derive(Debug, Clone)]
pub enum MempoolRejection {
    PoolFull,
    DuplicateLinkTag([u8; 32]),
    MissingInputs { missing: Vec<OutPoint> },
    OrphanLimit,
    CoinbaseForbidden,
}

#[derive(Debug, Clone)]
pub enum MempoolAddOutcome {
    Accepted { txid: TxId },
    Duplicate,
    StoredOrphan { missing: Vec<OutPoint> },
    Rejected(MempoolRejection),
}

#[derive(Default)]
struct TxPoolInner {
    entries: HashMap<TxId, TxEntry>,
    link_tags: HashSet<[u8; 32]>,
    bytes_used: usize,
    max_bytes: usize,
    max_orphans: usize,
    orphans: HashMap<TxId, OrphanEntry>,
}

pub struct TxPool {
    inner: Mutex<TxPoolInner>,
}

impl TxPool {
    pub fn new(max_bytes: usize, max_orphans: usize) -> Self {
        Self {
            inner: Mutex::new(TxPoolInner {
                max_bytes,
                max_orphans,
                ..Default::default()
            }),
        }
    }

    pub fn accept_transaction<F>(
        &self,
        tx: Tx,
        bytes_hint: Option<Vec<u8>>,
        mut is_available: F,
    ) -> MempoolAddOutcome
    where
        F: FnMut(&[u8; 32], u32) -> bool,
    {
        if tx.inputs.is_empty() {
            return MempoolAddOutcome::Rejected(MempoolRejection::CoinbaseForbidden);
        }
        let txid = tx.txid();
        let mut guard = self.inner.lock();
        if guard.entries.contains_key(&txid) || guard.orphans.contains_key(&txid) {
            return MempoolAddOutcome::Duplicate;
        }

        let encoded = match bytes_hint {
            Some(bytes) => bytes,
            None => match to_vec_cbor(&tx) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(error = ?err, "failed to serialize transaction for mempool");
                    return MempoolAddOutcome::Rejected(MempoolRejection::PoolFull);
                }
            },
        };
        let size = encoded.len();
        if guard.bytes_used + size > guard.max_bytes {
            return MempoolAddOutcome::Rejected(MempoolRejection::PoolFull);
        }

        if let Some(conflict) = duplicate_link_tag(&guard, &tx.inputs) {
            return MempoolAddOutcome::Rejected(MempoolRejection::DuplicateLinkTag(conflict));
        }

        let missing = missing_inputs(&guard, &tx, &mut is_available);
        if !missing.is_empty() {
            if guard.orphans.len() >= guard.max_orphans {
                return MempoolAddOutcome::Rejected(MempoolRejection::OrphanLimit);
            }
            let entry = OrphanEntry::new(tx, encoded, missing.clone());
            guard.orphans.insert(txid, entry);
            return MempoolAddOutcome::StoredOrphan { missing };
        }

        let link_tags: Vec<[u8; 32]> = tx.inputs.iter().map(|input| input.ann_link_tag).collect();
        let txid_bytes = *txid.as_bytes();
        let produced: Vec<OutPoint> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(index, _)| OutPoint::new(txid_bytes, index as u32))
            .collect();
        let entry = TxEntry::new(txid, encoded.clone(), link_tags, produced);
        guard.insert_entry(entry);
        MempoolAddOutcome::Accepted { txid }
    }

    pub fn contains(&self, txid: &TxId) -> bool {
        let guard = self.inner.lock();
        guard.entries.contains_key(txid)
    }

    pub fn txids(&self) -> Vec<TxId> {
        let guard = self.inner.lock();
        guard.entries.keys().cloned().collect()
    }

    pub fn get_bytes(&self, txid: &TxId) -> Option<Vec<u8>> {
        let guard = self.inner.lock();
        guard.entries.get(txid).map(|entry| entry.bytes.clone())
    }

    pub fn remove_confirmed(&self, txids: &[TxId]) {
        let mut guard = self.inner.lock();
        for txid in txids {
            if let Some(entry) = guard.entries.remove(txid) {
                guard.bytes_used = guard.bytes_used.saturating_sub(entry.size);
                for tag in entry.link_tags {
                    guard.link_tags.remove(&tag);
                }
            }
        }
    }

    pub fn resolve_orphans<F>(&self, mut is_available: F) -> Vec<(TxId, Vec<u8>)>
    where
        F: FnMut(&[u8; 32], u32) -> bool,
    {
        let mut guard = self.inner.lock();
        let mut promoted = Vec::new();
        let mut ready = Vec::new();
        for (txid, orphan) in guard.orphans.iter() {
            if orphan.missing.iter().all(|outpoint| {
                guard.has_output(&outpoint.txid, outpoint.index)
                    || is_available(&outpoint.txid, outpoint.index)
            }) {
                ready.push(*txid);
            }
        }

        for txid in ready {
            if let Some(orphan) = guard.orphans.remove(&txid) {
                if guard.bytes_used + orphan.bytes.len() > guard.max_bytes {
                    continue;
                }
                if let Some(conflict) = duplicate_link_tag(&guard, &orphan.tx.inputs) {
                    tracing::warn!(txid = %txid, conflict = ?conflict, "orphan conflicts on link tag");
                    continue;
                }
                let link_tags: Vec<[u8; 32]> = orphan
                    .tx
                    .inputs
                    .iter()
                    .map(|input| input.ann_link_tag)
                    .collect();
                let produced: Vec<OutPoint> = orphan
                    .tx
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(index, _)| OutPoint::new(*txid.as_bytes(), index as u32))
                    .collect();
                let bytes = orphan.bytes.clone();
                let entry = TxEntry::new(txid, orphan.bytes, link_tags, produced);
                guard.insert_entry(entry);
                promoted.push((txid, bytes));
            }
        }
        promoted
    }
}

fn duplicate_link_tag(inner: &TxPoolInner, inputs: &[Input]) -> Option<[u8; 32]> {
    let mut seen = HashSet::new();
    for input in inputs {
        if !seen.insert(input.ann_link_tag) {
            return Some(input.ann_link_tag);
        }
        if inner.link_tags.contains(&input.ann_link_tag) {
            return Some(input.ann_link_tag);
        }
        if inner.orphans.values().any(|entry| {
            entry
                .tx
                .inputs
                .iter()
                .any(|candidate| candidate.ann_link_tag == input.ann_link_tag)
        }) {
            return Some(input.ann_link_tag);
        }
    }
    None
}

fn missing_inputs<F>(inner: &TxPoolInner, tx: &Tx, mut is_available: F) -> Vec<OutPoint>
where
    F: FnMut(&[u8; 32], u32) -> bool,
{
    let mut missing = Vec::new();
    for input in &tx.inputs {
        if inner.has_output(&input.prev_txid, input.prev_index) {
            continue;
        }
        if is_available(&input.prev_txid, input.prev_index) {
            continue;
        }
        missing.push(OutPoint::new(input.prev_txid, input.prev_index));
    }
    missing
}

struct TxEntry {
    txid: TxId,
    bytes: Vec<u8>,
    size: usize,
    produced: Vec<OutPoint>,
    link_tags: Vec<[u8; 32]>,
}

impl TxEntry {
    fn new(txid: TxId, bytes: Vec<u8>, link_tags: Vec<[u8; 32]>, produced: Vec<OutPoint>) -> Self {
        let size = bytes.len();
        Self {
            txid,
            bytes,
            size,
            produced,
            link_tags,
        }
    }
}

struct OrphanEntry {
    tx: Tx,
    bytes: Vec<u8>,
    missing: Vec<OutPoint>,
}

impl OrphanEntry {
    fn new(tx: Tx, bytes: Vec<u8>, missing: Vec<OutPoint>) -> Self {
        Self { tx, bytes, missing }
    }
}

impl TxPoolInner {
    fn insert_entry(&mut self, entry: TxEntry) {
        self.bytes_used += entry.size;
        for tag in &entry.link_tags {
            self.link_tags.insert(*tag);
        }
        self.entries.insert(entry.txid, entry);
    }

    fn has_output(&self, txid: &[u8; 32], index: u32) -> bool {
        self.entries.values().any(|entry| {
            entry
                .produced
                .iter()
                .any(|outpoint| outpoint.txid == *txid && outpoint.index == index)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{AlgTag, Signature};
    use tx::{Input, Output, OutputMeta, Witness};

    fn sample_signature() -> Signature {
        Signature::new(AlgTag::Dilithium, vec![0u8; 64])
    }

    fn sample_output() -> Output {
        Output::new(vec![1, 2, 3], [0u8; 32], OutputMeta::default())
    }

    fn sample_tx(link_tag: [u8; 32]) -> Tx {
        let input = Input::new([1u8; 32], 0, link_tag, Vec::new(), sample_signature());
        Tx::new(vec![input], vec![sample_output()], Witness::default())
    }

    #[test]
    fn rejects_coinbase_transactions() {
        let pool = TxPool::new(10_000, 4);
        let tx = Tx::new(vec![], vec![sample_output()], Witness::default());
        match pool.accept_transaction(tx, None, |_txid, _| true) {
            MempoolAddOutcome::Rejected(MempoolRejection::CoinbaseForbidden) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn detects_duplicate_link_tags() {
        let pool = TxPool::new(10_000, 4);
        let tx = sample_tx([42u8; 32]);
        let result = pool.accept_transaction(tx.clone(), None, |_txid, _| true);
        assert!(matches!(result, MempoolAddOutcome::Accepted { .. }));
        let mut conflicting = sample_tx([42u8; 32]);
        conflicting.inputs[0].prev_index = 1;
        let result = pool.accept_transaction(conflicting, None, |_txid, _| true);
        assert!(matches!(
            result,
            MempoolAddOutcome::Rejected(MempoolRejection::DuplicateLinkTag(_))
        ));
    }

    #[test]
    fn stores_and_promotes_orphans() {
        let pool = TxPool::new(10_000, 4);
        let tx = sample_tx([7u8; 32]);
        let result = pool.accept_transaction(tx, None, |_txid, _| false);
        match result {
            MempoolAddOutcome::StoredOrphan { missing } => {
                assert_eq!(missing.len(), 1);
            }
            other => panic!("expected orphan, got {other:?}"),
        }
        let promoted = pool.resolve_orphans(|_, _| true);
        assert_eq!(promoted.len(), 1);
    }
}
