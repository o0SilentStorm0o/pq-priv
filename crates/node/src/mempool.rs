use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use codec::to_vec_cbor;
use parking_lot::Mutex;
use tx::{Input, Tx, TxId};
use utxo::OutPoint;

/// Describes why the mempool rejected a transaction.
#[derive(Debug, Clone)]
pub enum MempoolRejection {
    PoolFull,
    FeeTooLow { required: u64, actual: u64 },
    DuplicateLinkTag([u8; 32]),
    MissingInputs { missing: Vec<OutPoint> },
    OrphanLimit,
    CoinbaseForbidden,
}

/// Result of attempting to add a transaction to the mempool.
#[derive(Debug, Clone)]
pub enum MempoolAddOutcome {
    Accepted { txid: TxId },
    Duplicate,
    StoredOrphan { missing: Vec<OutPoint> },
    Rejected(MempoolRejection),
}

/// Configuration parameters governing mempool behaviour.
#[derive(Clone, Debug)]
pub struct TxPoolConfig {
    pub max_bytes: usize,
    pub max_orphans: usize,
    pub min_relay_fee_sat_vb: u64,
    pub orphan_ttl: Duration,
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        Self {
            max_bytes: 50_000_000,
            max_orphans: 5_000,
            min_relay_fee_sat_vb: 10,
            orphan_ttl: Duration::from_secs(600),
        }
    }
}

/// Summary statistics describing the current pool state.
#[derive(Debug, Clone, Copy)]
pub struct TxPoolStats {
    pub tx_count: usize,
    pub total_bytes: usize,
    pub orphan_count: usize,
}

/// Thread-safe mempool implementation with basic hygiene policies.
pub struct TxPool {
    inner: Mutex<TxPoolInner>,
    min_relay_fee_sat_vb: u64,
    orphan_ttl: Duration,
}

impl TxPool {
    pub fn new(config: TxPoolConfig) -> Self {
        Self {
            inner: Mutex::new(TxPoolInner::new(config.max_bytes, config.max_orphans)),
            min_relay_fee_sat_vb: config.min_relay_fee_sat_vb,
            orphan_ttl: config.orphan_ttl,
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

        let fee_sat = extract_fee_sat(&tx);
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
        let fee_rate = calculate_fee_rate(fee_sat, size);
        if fee_rate < self.min_relay_fee_sat_vb {
            return MempoolAddOutcome::Rejected(MempoolRejection::FeeTooLow {
                required: self.min_relay_fee_sat_vb,
                actual: fee_rate,
            });
        }

        let mut guard = self.inner.lock();
        guard.purge_expired_orphans(self.orphan_ttl);
        let txid = tx.txid();
        if guard.entries.contains_key(&txid) || guard.orphans.contains_key(&txid) {
            return MempoolAddOutcome::Duplicate;
        }

        let missing = missing_inputs(&guard, &tx, |txid, index| is_available(txid, index));
        if !missing.is_empty() {
            if guard.orphans.len() >= guard.max_orphans && !guard.remove_oldest_orphan() {
                return MempoolAddOutcome::Rejected(MempoolRejection::OrphanLimit);
            }
            let arrival_seq = guard.next_sequence();
            guard.orphans.insert(
                txid,
                OrphanEntry::new(tx, encoded, missing.clone(), fee_rate, arrival_seq),
            );
            return MempoolAddOutcome::StoredOrphan { missing };
        }

        if let Some(conflict) = duplicate_link_tag(&guard, &tx.inputs) {
            return MempoolAddOutcome::Rejected(MempoolRejection::DuplicateLinkTag(conflict));
        }

        if !guard.ensure_capacity(size, fee_rate) {
            return MempoolAddOutcome::Rejected(MempoolRejection::PoolFull);
        }

        let link_tags: Vec<[u8; 32]> = tx.inputs.iter().map(|input| input.ann_link_tag).collect();
        let produced: Vec<OutPoint> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(index, _)| OutPoint::new(*txid.as_bytes(), index as u32))
            .collect();
        let entry = TxEntry::new(
            txid,
            encoded,
            link_tags,
            produced,
            fee_rate,
            guard.next_sequence(),
        );
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

    #[allow(dead_code)]
    pub fn remove_confirmed(&self, txids: &[TxId]) {
        let mut guard = self.inner.lock();
        for txid in txids {
            guard.remove_entry(txid);
        }
    }

    #[allow(dead_code)]
    pub fn resolve_orphans<F>(&self, mut is_available: F) -> Vec<(TxId, Vec<u8>)>
    where
        F: FnMut(&[u8; 32], u32) -> bool,
    {
        let mut guard = self.inner.lock();
        guard.purge_expired_orphans(self.orphan_ttl);
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
                if orphan.fee_per_vb < self.min_relay_fee_sat_vb {
                    continue;
                }
                if let Some(conflict) = duplicate_link_tag(&guard, &orphan.tx.inputs) {
                    tracing::warn!(%txid, conflict = ?conflict, "orphan conflicts on link tag");
                    continue;
                }
                if !guard.ensure_capacity(orphan.size, orphan.fee_per_vb) {
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
                let entry = TxEntry::new(
                    txid,
                    orphan.bytes.clone(),
                    link_tags,
                    produced,
                    orphan.fee_per_vb,
                    guard.next_sequence(),
                );
                guard.insert_entry(entry);
                promoted.push((txid, orphan.bytes));
            }
        }
        promoted
    }

    pub fn stats(&self) -> TxPoolStats {
        let mut guard = self.inner.lock();
        guard.purge_expired_orphans(self.orphan_ttl);
        TxPoolStats {
            tx_count: guard.entries.len(),
            total_bytes: guard.bytes_used,
            orphan_count: guard.orphans.len(),
        }
    }
}

struct TxPoolInner {
    entries: HashMap<TxId, TxEntry>,
    link_tags: HashSet<[u8; 32]>,
    bytes_used: usize,
    max_bytes: usize,
    max_orphans: usize,
    orphans: HashMap<TxId, OrphanEntry>,
    next_seq: u64,
}

impl TxPoolInner {
    fn new(max_bytes: usize, max_orphans: usize) -> Self {
        Self {
            entries: HashMap::new(),
            link_tags: HashSet::new(),
            bytes_used: 0,
            max_bytes,
            max_orphans,
            orphans: HashMap::new(),
            next_seq: 0,
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    fn insert_entry(&mut self, entry: TxEntry) {
        self.bytes_used = self.bytes_used.saturating_add(entry.size);
        for tag in &entry.link_tags {
            self.link_tags.insert(*tag);
        }
        self.entries.insert(entry.txid, entry);
    }

    fn remove_entry(&mut self, txid: &TxId) {
        if let Some(entry) = self.entries.remove(txid) {
            self.bytes_used = self.bytes_used.saturating_sub(entry.size);
            for tag in entry.link_tags {
                self.link_tags.remove(&tag);
            }
        }
    }

    fn ensure_capacity(&mut self, required: usize, incoming_fee_rate: u64) -> bool {
        while self.bytes_used + required > self.max_bytes {
            let victim = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.fee_per_vb <= incoming_fee_rate)
                .min_by(|a, b| compare_entries(a.1, b.1))
                .map(|(txid, _)| *txid);
            match victim {
                Some(txid) => self.remove_entry(&txid),
                None => return false,
            }
        }
        true
    }

    fn has_output(&self, txid: &[u8; 32], index: u32) -> bool {
        self.entries.values().any(|entry| {
            entry
                .produced
                .iter()
                .any(|outpoint| outpoint.txid == *txid && outpoint.index == index)
        })
    }

    fn purge_expired_orphans(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.orphans
            .retain(|_, orphan| now.duration_since(orphan.received_at) <= ttl);
    }

    fn remove_oldest_orphan(&mut self) -> bool {
        if self.orphans.is_empty() {
            return false;
        }
        if let Some((txid, _)) = self
            .orphans
            .iter()
            .min_by(|a, b| a.1.seq.cmp(&b.1.seq))
            .map(|(txid, entry)| (*txid, entry.seq))
        {
            self.orphans.remove(&txid);
            true
        } else {
            false
        }
    }
}

struct TxEntry {
    txid: TxId,
    bytes: Vec<u8>,
    size: usize,
    produced: Vec<OutPoint>,
    link_tags: Vec<[u8; 32]>,
    fee_per_vb: u64,
    seq: u64,
}

impl TxEntry {
    fn new(
        txid: TxId,
        bytes: Vec<u8>,
        link_tags: Vec<[u8; 32]>,
        produced: Vec<OutPoint>,
        fee_per_vb: u64,
        seq: u64,
    ) -> Self {
        let size = bytes.len();
        Self {
            txid,
            bytes,
            size,
            produced,
            link_tags,
            fee_per_vb,
            seq,
        }
    }
}

struct OrphanEntry {
    tx: Tx,
    bytes: Vec<u8>,
    missing: Vec<OutPoint>,
    fee_per_vb: u64,
    size: usize,
    received_at: Instant,
    seq: u64,
}

impl OrphanEntry {
    fn new(tx: Tx, bytes: Vec<u8>, missing: Vec<OutPoint>, fee_per_vb: u64, seq: u64) -> Self {
        let size = bytes.len();
        Self {
            tx,
            bytes,
            missing,
            fee_per_vb,
            size,
            received_at: Instant::now(),
            seq,
        }
    }
}

fn compare_entries(a: &TxEntry, b: &TxEntry) -> Ordering {
    match a.fee_per_vb.cmp(&b.fee_per_vb) {
        Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
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

fn extract_fee_sat(tx: &Tx) -> u64 {
    if tx.witness.extra.len() >= 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&tx.witness.extra[..8]);
        u64::from_le_bytes(buf)
    } else {
        0
    }
}

fn calculate_fee_rate(fee_sat: u64, size: usize) -> u64 {
    if size == 0 {
        return u64::MAX;
    }
    fee_sat
        .saturating_mul(1_000)
        .checked_div(size as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    use codec::to_vec_cbor;
    use crypto::{AlgTag, PublicKey, Signature};
    use tx::{Input, Output, OutputMeta, Witness};

    fn pool_with_defaults() -> TxPool {
        TxPool::new(TxPoolConfig::default())
    }

    fn pool_with_config(config: TxPoolConfig) -> TxPool {
        TxPool::new(config)
    }

    fn sample_signature() -> Signature {
        #[cfg(feature = "dev_stub_signing")]
        let alg = AlgTag::Ed25519;
        #[cfg(not(feature = "dev_stub_signing"))]
        let alg = AlgTag::Dilithium2;
        Signature::new(alg, vec![0u8; 64])
    }

    fn sample_public_key() -> PublicKey {
        PublicKey::from_bytes(vec![2u8; 32])
    }

    fn sample_output() -> Output {
        Output::new(vec![1, 2, 3], 100, OutputMeta::default())
    }

    fn sample_tx_with_fee(link_tag: [u8; 32], fee_sat: u64) -> Tx {
        let input = Input::new(
            [1u8; 32],
            0,
            link_tag,
            sample_public_key(),
            vec![0x42],
            sample_signature(),
        );
        let mut tx = Tx::new(vec![input], vec![sample_output()], Witness::default());
        tx.witness.extra = fee_sat.to_le_bytes().to_vec();
        tx
    }

    #[test]
    fn rejects_coinbase_transactions() {
        let pool = pool_with_defaults();
        let tx = Tx::new(vec![], vec![sample_output()], Witness::default());
        match pool.accept_transaction(tx, None, |_txid, _| true) {
            MempoolAddOutcome::Rejected(MempoolRejection::CoinbaseForbidden) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn detects_duplicate_link_tags() {
        let pool = pool_with_defaults();
        let tx = sample_tx_with_fee([42u8; 32], 1_000);
        let result = pool.accept_transaction(tx.clone(), None, |_txid, _| true);
        assert!(matches!(result, MempoolAddOutcome::Accepted { .. }));
        let mut conflicting = sample_tx_with_fee([42u8; 32], 1_000);
        conflicting.inputs[0].prev_index = 1;
        let result = pool.accept_transaction(conflicting, None, |_txid, _| true);
        assert!(matches!(
            result,
            MempoolAddOutcome::Rejected(MempoolRejection::DuplicateLinkTag(_))
        ));
    }

    #[test]
    fn enforces_min_relay_fee() {
        let config = TxPoolConfig {
            min_relay_fee_sat_vb: 500,
            ..Default::default()
        };
        let pool = pool_with_config(config);
        let low_fee_tx = sample_tx_with_fee([10u8; 32], 1);
        let result = pool.accept_transaction(low_fee_tx, None, |_txid, _| true);
        assert!(matches!(
            result,
            MempoolAddOutcome::Rejected(MempoolRejection::FeeTooLow { .. })
        ));
        let high_fee_tx = sample_tx_with_fee([11u8; 32], 100_000);
        let result = pool.accept_transaction(high_fee_tx, None, |_txid, _| true);
        assert!(matches!(result, MempoolAddOutcome::Accepted { .. }));
    }

    #[test]
    fn evicts_low_fee_transactions_when_full() {
        let low_fee_tx = sample_tx_with_fee([1u8; 32], 1_000);
        let low_fee_id = low_fee_tx.txid();
        let low_encoded = to_vec_cbor(&low_fee_tx).unwrap();
        let high_fee_tx = sample_tx_with_fee([2u8; 32], 100_000);
        let high_id = high_fee_tx.txid();
        let max_bytes = low_encoded.len() + 10;
        let config = TxPoolConfig {
            max_bytes,
            ..Default::default()
        };
        let pool = pool_with_config(config);
        assert!(matches!(
            pool.accept_transaction(low_fee_tx, Some(low_encoded), |_txid, _| true),
            MempoolAddOutcome::Accepted { .. }
        ));
        assert!(matches!(
            pool.accept_transaction(high_fee_tx, None, |_txid, _| true),
            MempoolAddOutcome::Accepted { .. }
        ));
        assert!(!pool.contains(&low_fee_id));
        assert!(pool.contains(&high_id));
    }

    #[test]
    fn stores_and_promotes_orphans_with_expiry() {
        let config = TxPoolConfig {
            orphan_ttl: Duration::from_millis(10),
            ..Default::default()
        };
        let pool = pool_with_config(config);
        let tx = sample_tx_with_fee([7u8; 32], 1_000);
        let result = pool.accept_transaction(tx, None, |_txid, _| false);
        match result {
            MempoolAddOutcome::StoredOrphan { missing } => {
                assert_eq!(missing.len(), 1);
            }
            other => panic!("expected orphan, got {other:?}"),
        }
        thread::sleep(Duration::from_millis(20));
        assert_eq!(pool.stats().orphan_count, 0);
    }
}
