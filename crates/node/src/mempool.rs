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
    FeeTooLow {
        required: u64,
        actual: u64,
    },
    DuplicateLinkTag([u8; 32]),
    MissingInputs {
        missing: Vec<OutPoint>,
    },
    OrphanLimit,
    CoinbaseForbidden,
    /// TX v2 used when STARK feature is disabled
    StarkNotEnabled,
    /// Nullifier already spent (double-spend attempt)
    DuplicateNullifier([u8; 32]),
    /// TX v2 anonymity set size out of allowed range (32-256)
    InvalidAnonymitySetSize {
        actual: usize,
    },
    /// Too many pending TX v2 transactions (DoS protection)
    TooManyPendingV2 {
        limit: usize,
    },
    /// TX v2 fee too low for computational cost
    InsufficientStarkFee {
        required: u64,
        actual: u64,
    },
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
    /// Maximum number of pending TX v2 (STARK) transactions per peer (DoS protection)
    pub max_pending_v2_per_peer: usize,
    /// Base fee rate for TX v2 STARK verification (sat/vbyte multiplier for computational cost)
    pub stark_fee_multiplier: u64,
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        Self {
            max_bytes: 50_000_000,
            max_orphans: 5_000,
            min_relay_fee_sat_vb: 10,
            orphan_ttl: Duration::from_secs(600),
            max_pending_v2_per_peer: 10,
            stark_fee_multiplier: 5, // TX v2 requires 5x higher fee due to verification cost
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
    max_pending_v2_per_peer: usize,
    stark_fee_multiplier: u64,
}

/// Anonymity set size bounds for TX v2 (STARK-based transactions)
const MIN_ANONYMITY_SET: usize = 32;
const MAX_ANONYMITY_SET: usize = 256;

impl TxPool {
    pub fn new(config: TxPoolConfig) -> Self {
        Self {
            inner: Mutex::new(TxPoolInner::new(config.max_bytes, config.max_orphans)),
            min_relay_fee_sat_vb: config.min_relay_fee_sat_vb,
            orphan_ttl: config.orphan_ttl,
            max_pending_v2_per_peer: config.max_pending_v2_per_peer,
            stark_fee_multiplier: config.stark_fee_multiplier,
        }
    }

    pub fn accept_transaction<F, N>(
        &self,
        tx: Tx,
        bytes_hint: Option<Vec<u8>>,
        mut is_available: F,
        stark_enabled: bool,
        mut is_nullifier_spent: N,
    ) -> MempoolAddOutcome
    where
        F: FnMut(&[u8; 32], u32) -> bool,
        N: FnMut(&[u8; 32]) -> bool,
    {
        if tx.inputs.is_empty() {
            return MempoolAddOutcome::Rejected(MempoolRejection::CoinbaseForbidden);
        }

        // TX v2 validation
        if tx.is_v2() {
            if !stark_enabled {
                return MempoolAddOutcome::Rejected(MempoolRejection::StarkNotEnabled);
            }

            // Check for duplicate nullifiers (double-spend)
            if let Some(nullifier) = &tx.witness.nullifier
                && is_nullifier_spent(nullifier.as_bytes())
            {
                return MempoolAddOutcome::Rejected(MempoolRejection::DuplicateNullifier(
                    *nullifier.as_bytes(),
                ));
            }

            // Validate anonymity set size (32-256)
            // The anonymity set size is encoded in witness.extra as the first 2 bytes (u16, little-endian)
            // This is a simplified approach - in production, it would be extracted from STARK proof metadata
            
            let anonymity_set_size = if tx.witness.extra.len() >= 2 {
                u16::from_le_bytes([tx.witness.extra[0], tx.witness.extra[1]]) as usize
            } else {
                0
            };

            if !(MIN_ANONYMITY_SET..=MAX_ANONYMITY_SET).contains(&anonymity_set_size) {
                return MempoolAddOutcome::Rejected(MempoolRejection::InvalidAnonymitySetSize {
                    actual: anonymity_set_size,
                });
            }

            // Ensure nullifier is present
            if tx.witness.nullifier.is_none() {
                return MempoolAddOutcome::Rejected(MempoolRejection::InvalidAnonymitySetSize {
                    actual: 0,
                });
            }
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
        
        // Base fee check (applies to all transactions)
        if fee_rate < self.min_relay_fee_sat_vb {
            return MempoolAddOutcome::Rejected(MempoolRejection::FeeTooLow {
                required: self.min_relay_fee_sat_vb,
                actual: fee_rate,
            });
        }

        // TX v2 requires higher fee due to computational cost of STARK verification
        // CPU time for STARK verify ≈ 5-10ms, which is ~50x slower than basic signature verify
        // Therefore we require stark_fee_multiplier * base_fee
        if tx.is_v2() {
            let required_v2_fee = self.min_relay_fee_sat_vb * self.stark_fee_multiplier;
            #[cfg(test)]
            eprintln!("TX v2 fee check: fee_rate={} sat/kb, required={} sat/kb", fee_rate, required_v2_fee);
            if fee_rate < required_v2_fee {
                return MempoolAddOutcome::Rejected(MempoolRejection::InsufficientStarkFee {
                    required: required_v2_fee,
                    actual: fee_rate,
                });
            }
        }

        let mut guard = self.inner.lock();
        guard.purge_expired_orphans(self.orphan_ttl);
        
        // DoS protection: Limit number of pending TX v2 transactions
        // STARK verification is computationally expensive (~5-10ms per tx)
        // Allowing too many pending v2 txs could enable CPU exhaustion attacks
        if tx.is_v2() && guard.v2_count >= self.max_pending_v2_per_peer {
            return MempoolAddOutcome::Rejected(MempoolRejection::TooManyPendingV2 {
                limit: self.max_pending_v2_per_peer,
            });
        }
        
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

        let is_v2 = tx.is_v2();
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
            is_v2,
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
                let is_v2 = orphan.tx.is_v2();
                let entry = TxEntry::new(
                    txid,
                    orphan.bytes.clone(),
                    link_tags,
                    produced,
                    orphan.fee_per_vb,
                    guard.next_sequence(),
                    is_v2,
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
    /// Count of TX v2 (STARK) transactions in mempool (for DoS protection)
    v2_count: usize,
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
            v2_count: 0,
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
        if entry.is_v2 {
            self.v2_count = self.v2_count.saturating_add(1);
        }
        self.entries.insert(entry.txid, entry);
    }

    fn remove_entry(&mut self, txid: &TxId) {
        if let Some(entry) = self.entries.remove(txid) {
            self.bytes_used = self.bytes_used.saturating_sub(entry.size);
            for tag in entry.link_tags {
                self.link_tags.remove(&tag);
            }
            if entry.is_v2 {
                self.v2_count = self.v2_count.saturating_sub(1);
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
    is_v2: bool,
}

impl TxEntry {
    fn new(
        txid: TxId,
        bytes: Vec<u8>,
        link_tags: Vec<[u8; 32]>,
        produced: Vec<OutPoint>,
        fee_per_vb: u64,
        seq: u64,
        is_v2: bool,
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
            is_v2,
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
    // For TX v2, witness.extra format is: [anonymity_set_size (2 bytes, u16 LE)] || [fee (8 bytes, u64 LE)] || [other data]
    // For TX v1, witness.extra format is: [fee (8 bytes, u64 LE)] || [other data]
    let offset = if tx.is_v2() { 2 } else { 0 };
    
    if tx.witness.extra.len() >= offset + 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&tx.witness.extra[offset..offset + 8]);
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
    use tx::{Input, Nullifier, Output, OutputMeta, SpendTag, Witness};

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
        match pool.accept_transaction(tx, None, |_txid, _| true, false, |_| false) {
            MempoolAddOutcome::Rejected(MempoolRejection::CoinbaseForbidden) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn detects_duplicate_link_tags() {
        let pool = pool_with_defaults();
        let tx = sample_tx_with_fee([42u8; 32], 1_000);
        let result = pool.accept_transaction(tx.clone(), None, |_txid, _| true, false, |_| false);
        assert!(matches!(result, MempoolAddOutcome::Accepted { .. }));

        // Create a different TX with same link tag but different output value to get different TXID
        let input = Input::new(
            [2u8; 32], // Different prev_txid
            0,
            [42u8; 32], // Same link tag!
            sample_public_key(),
            vec![0x42],
            sample_signature(),
        );
        let output = Output::new(vec![1, 2, 3], 200, OutputMeta::default()); // Different amount
        let mut conflicting = Tx::new(vec![input], vec![output], Witness::default());
        conflicting.witness.extra = 2_000u64.to_le_bytes().to_vec();

        let result = pool.accept_transaction(conflicting, None, |_txid, _| true, false, |_| false);
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
        let result = pool.accept_transaction(low_fee_tx, None, |_txid, _| true, false, |_| false);
        assert!(matches!(
            result,
            MempoolAddOutcome::Rejected(MempoolRejection::FeeTooLow { .. })
        ));
        let high_fee_tx = sample_tx_with_fee([11u8; 32], 100_000);
        let result = pool.accept_transaction(high_fee_tx, None, |_txid, _| true, false, |_| false);
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
            pool.accept_transaction(
                low_fee_tx,
                Some(low_encoded),
                |_txid, _| true,
                false,
                |_| false
            ),
            MempoolAddOutcome::Accepted { .. }
        ));
        assert!(matches!(
            pool.accept_transaction(high_fee_tx, None, |_txid, _| true, false, |_| false),
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
        let result = pool.accept_transaction(tx, None, |_txid, _| false, false, |_| false);
        match result {
            MempoolAddOutcome::StoredOrphan { missing } => {
                assert_eq!(missing.len(), 1);
            }
            other => panic!("expected orphan, got {other:?}"),
        }
        thread::sleep(Duration::from_millis(20));
        assert_eq!(pool.stats().orphan_count, 0);
    }

    #[test]
    fn rejects_tx_v2_when_stark_disabled() {
        use tx::{Nullifier, SpendTag};

        let pool = pool_with_defaults();
        let output = sample_output();
        let witness = Witness {
            range_proofs: Vec::new(),
            stamp: 1000,
            extra: vec![],
            nullifier: Some(Nullifier::new([1u8; 32])),
            spend_tag: Some(SpendTag::new([2u8; 32])),
        };
        let input = Input::new(
            [1u8; 32],
            0,
            [10u8; 32],
            sample_public_key(),
            vec![0x42],
            sample_signature(),
        );
        let tx_v2 = Tx::with_version(2, vec![input], vec![output], witness);

        let result = pool.accept_transaction(tx_v2, None, |_, _| true, false, |_| false);
        assert!(matches!(
            result,
            MempoolAddOutcome::Rejected(MempoolRejection::StarkNotEnabled)
        ));
    }

    #[test]
    fn accepts_tx_v2_when_stark_enabled() {
        use tx::{Nullifier, SpendTag};

        let pool = pool_with_defaults();
        let output = sample_output();
        let mut witness = Witness {
            range_proofs: Vec::new(),
            stamp: 1000,
            extra: vec![64, 0], // Anonymity set size = 64
            nullifier: Some(Nullifier::new([1u8; 32])),
            spend_tag: Some(SpendTag::new([2u8; 32])),
        };
        witness.extra.extend_from_slice(&10_000u64.to_le_bytes()); // Add fee
        
        let input = Input::new(
            [1u8; 32],
            0,
            [10u8; 32],
            sample_public_key(),
            vec![0x42],
            sample_signature(),
        );
        let tx_v2 = Tx::with_version(2, vec![input], vec![output], witness);

        let result = pool.accept_transaction(tx_v2, None, |_, _| true, true, |_| false);
        assert!(matches!(result, MempoolAddOutcome::Accepted { .. }));
    }

    #[test]
    fn rejects_duplicate_nullifier() {
        use tx::{Nullifier, SpendTag};

        let pool = pool_with_defaults();
        let nullifier = [42u8; 32];

        // First TX should be accepted
        let output1 = sample_output();
        let mut witness1 = Witness {
            range_proofs: Vec::new(),
            stamp: 1000,
            extra: vec![64, 0], // Anonymity set size = 64
            nullifier: Some(Nullifier::new(nullifier)),
            spend_tag: Some(SpendTag::new([1u8; 32])),
        };
        witness1.extra.extend_from_slice(&10_000u64.to_le_bytes());
        
        let input1 = Input::new(
            [1u8; 32],
            0,
            [10u8; 32],
            sample_public_key(),
            vec![0x42],
            sample_signature(),
        );
        let tx1 = Tx::with_version(2, vec![input1], vec![output1], witness1);

        let result1 = pool.accept_transaction(tx1, None, |_, _| true, true, |_| false);
        assert!(matches!(result1, MempoolAddOutcome::Accepted { .. }));

        // Second TX with same nullifier should be rejected
        let output2 = sample_output();
        let mut witness2 = Witness {
            range_proofs: Vec::new(),
            stamp: 1001,
            extra: vec![64, 0], // Anonymity set size = 64
            nullifier: Some(Nullifier::new(nullifier)),
            spend_tag: Some(SpendTag::new([2u8; 32])),
        };
        witness2.extra.extend_from_slice(&10_000u64.to_le_bytes());
        
        let input2 = Input::new(
            [2u8; 32],
            0,
            [20u8; 32],
            sample_public_key(),
            vec![0x43],
            sample_signature(),
        );
        let tx2 = Tx::with_version(2, vec![input2], vec![output2], witness2);

        // Simulate nullifier already spent in chain
        let result2 = pool.accept_transaction(tx2, None, |_, _| true, true, |n| n == &nullifier);
        assert!(matches!(
            result2,
            MempoolAddOutcome::Rejected(MempoolRejection::DuplicateNullifier(_))
        ));
    }

    #[test]
    fn rejects_invalid_anonymity_set_size() {
        let pool = pool_with_defaults();
        let nullifier = [99u8; 32];
        let output = sample_output();

        // Anonymity set size too small (< 32)
        let mut witness_small = Witness {
            range_proofs: Vec::new(),
            stamp: 1000,
            extra: vec![16, 0], // 16 in little-endian u16
            nullifier: Some(Nullifier::new(nullifier)),
            spend_tag: Some(SpendTag::new([1u8; 32])),
        };
        witness_small.extra.extend_from_slice(&1_000u64.to_le_bytes());
        
        let input = Input::new(
            [1u8; 32],
            0,
            [10u8; 32],
            sample_public_key(),
            vec![0x42],
            sample_signature(),
        );
        let tx_small = Tx::with_version(2, vec![input.clone()], vec![output.clone()], witness_small);

        let result = pool.accept_transaction(tx_small, None, |_, _| true, true, |_| false);
        assert!(matches!(
            result,
            MempoolAddOutcome::Rejected(MempoolRejection::InvalidAnonymitySetSize { actual: 16 })
        ));

        // Anonymity set size too large (> 256)
        let mut witness_large = Witness {
            range_proofs: Vec::new(),
            stamp: 1001,
            extra: vec![0, 2], // 512 in little-endian u16
            nullifier: Some(Nullifier::new([100u8; 32])),
            spend_tag: Some(SpendTag::new([2u8; 32])),
        };
        witness_large.extra.extend_from_slice(&1_000u64.to_le_bytes());
        
        let tx_large = Tx::with_version(2, vec![input], vec![output], witness_large);

        let result = pool.accept_transaction(tx_large, None, |_, _| true, true, |_| false);
        assert!(matches!(
            result,
            MempoolAddOutcome::Rejected(MempoolRejection::InvalidAnonymitySetSize { actual: 512 })
        ));
    }

    #[test]
    fn enforces_higher_fee_for_tx_v2() {
        let nullifier = [88u8; 32];
        let output = sample_output();

        // First test: TX v2 with sufficient fee should be accepted
        {
            let config = TxPoolConfig {
                min_relay_fee_sat_vb: 10, // Actually 10 sat/kilobyte
                stark_fee_multiplier: 5,   // Requires 50 sat/kilobyte for TX v2
                ..Default::default()
            };
            let pool = pool_with_config(config);

            let mut witness = Witness {
                range_proofs: Vec::new(),
                stamp: 1000,
                extra: vec![64, 0], // 64 in little-endian u16
                nullifier: Some(Nullifier::new(nullifier)),
                spend_tag: Some(SpendTag::new([1u8; 32])),
            };
            // 100 sats / 613 bytes * 1000 = ~163 sat/kilobyte > 50 required ✓
            witness.extra.extend_from_slice(&100u64.to_le_bytes());
            
            let input = Input::new(
                [1u8; 32],
                0,
                [10u8; 32],
                sample_public_key(),
                vec![0x42],
                sample_signature(),
            );
            let tx_high_fee = Tx::with_version(2, vec![input], vec![output.clone()], witness);

            let result = pool.accept_transaction(tx_high_fee, None, |_, _| true, true, |_| false);
            assert!(matches!(result, MempoolAddOutcome::Accepted { .. }));
        }

        // Second test: TX v2 with insufficient fee should be rejected (separate pool)
        {
            let config = TxPoolConfig {
                min_relay_fee_sat_vb: 10,
                stark_fee_multiplier: 5,
                ..Default::default()
            };
            let pool = pool_with_config(config);

            let mut witness_low_fee = Witness {
                range_proofs: Vec::new(),
                stamp: 1001,
                extra: vec![64, 0],
                nullifier: Some(Nullifier::new([89u8; 32])),
                spend_tag: Some(SpendTag::new([2u8; 32])),
            };
            // 20 sats / 613 bytes * 1000 = ~32 sat/kilobyte
            // This is > 10 base fee but < 50 required for TX v2 ✓
            witness_low_fee.extra.extend_from_slice(&20u64.to_le_bytes());
            
            let input_low_fee = Input::new(
                [2u8; 32], // Different prev_txid
                0,
                [20u8; 32], // Different link tag
                sample_public_key(),
                vec![0x42],
                sample_signature(),
            );
            let tx_low_fee = Tx::with_version(2, vec![input_low_fee], vec![output], witness_low_fee);

            let result = pool.accept_transaction(tx_low_fee, None, |_, _| true, true, |_| false);
            assert!(matches!(
                result,
                MempoolAddOutcome::Rejected(MempoolRejection::InsufficientStarkFee { .. })
            ));
        }
    }

    #[test]
    fn enforces_dos_limit_on_pending_v2() {
        let config = TxPoolConfig {
            max_pending_v2_per_peer: 2,
            min_relay_fee_sat_vb: 10,
            stark_fee_multiplier: 5,
            ..Default::default()
        };
        let pool = pool_with_config(config);

        let output = sample_output();

        // Accept first TX v2
        let mut witness1 = Witness {
            range_proofs: Vec::new(),
            stamp: 1000,
            extra: vec![64, 0],
            nullifier: Some(Nullifier::new([1u8; 32])),
            spend_tag: Some(SpendTag::new([1u8; 32])),
        };
        witness1.extra.extend_from_slice(&10_000u64.to_le_bytes());
        
        let input1 = Input::new(
            [1u8; 32],
            0,
            [10u8; 32],
            sample_public_key(),
            vec![0x42],
            sample_signature(),
        );
        let tx1 = Tx::with_version(2, vec![input1], vec![output.clone()], witness1);
        let result1 = pool.accept_transaction(tx1, None, |_, _| true, true, |_| false);
        assert!(matches!(result1, MempoolAddOutcome::Accepted { .. }));

        // Accept second TX v2
        let mut witness2 = Witness {
            range_proofs: Vec::new(),
            stamp: 1001,
            extra: vec![64, 0],
            nullifier: Some(Nullifier::new([2u8; 32])),
            spend_tag: Some(SpendTag::new([2u8; 32])),
        };
        witness2.extra.extend_from_slice(&10_000u64.to_le_bytes());
        
        let input2 = Input::new(
            [2u8; 32],
            0,
            [20u8; 32],
            sample_public_key(),
            vec![0x43],
            sample_signature(),
        );
        let tx2 = Tx::with_version(2, vec![input2], vec![output.clone()], witness2);
        let result2 = pool.accept_transaction(tx2, None, |_, _| true, true, |_| false);
        assert!(matches!(result2, MempoolAddOutcome::Accepted { .. }));

        // Third TX v2 should be rejected (DoS limit = 2)
        let mut witness3 = Witness {
            range_proofs: Vec::new(),
            stamp: 1002,
            extra: vec![64, 0],
            nullifier: Some(Nullifier::new([3u8; 32])),
            spend_tag: Some(SpendTag::new([3u8; 32])),
        };
        witness3.extra.extend_from_slice(&10_000u64.to_le_bytes());
        
        let input3 = Input::new(
            [3u8; 32],
            0,
            [30u8; 32],
            sample_public_key(),
            vec![0x44],
            sample_signature(),
        );
        let tx3 = Tx::with_version(2, vec![input3], vec![output], witness3);
        let result3 = pool.accept_transaction(tx3, None, |_, _| true, true, |_| false);
        assert!(matches!(
            result3,
            MempoolAddOutcome::Rejected(MempoolRejection::TooManyPendingV2 { limit: 2 })
        ));
    }
}
