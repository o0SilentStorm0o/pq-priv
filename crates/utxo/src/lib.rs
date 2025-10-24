//! In-memory UTXO management primitives supporting double-spend detection.

use std::collections::{BTreeMap, HashSet};

use consensus::Block;
use crypto::{self, VerifyItem, balance_commitments, get_max_proofs_per_block, verify_range};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tx::{self, Output, Tx};

/// Unique reference to a transaction output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub index: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], index: u32) -> Self {
        Self { txid, index }
    }
}

/// Metadata stored alongside each live UTXO.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputRecord {
    pub output: Output,
    pub block_height: u64,
    pub compact_index: u64,
}

impl OutputRecord {
    pub fn new(output: Output, block_height: u64, compact_index: u64) -> Self {
        Self {
            output,
            block_height,
            compact_index,
        }
    }
}

/// Errors surfaced by UTXO operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UtxoError {
    #[error("block contains no transactions")]
    EmptyBlock,
    #[error("coinbase transaction must be first and must not have inputs")]
    InvalidCoinbase,
    #[error("input references missing output {0:?}")]
    MissingOutPoint(OutPoint),
    #[error("input references same outpoint multiple times in block")]
    DuplicateOutPoint,
    #[error("linkability tag already seen: {0:?}")]
    DuplicateLinkTag([u8; 32]),
    #[error("one-of-many proof missing or malformed")]
    InvalidProof,
    #[error("signature failed to verify")]
    InvalidSignature,
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("confidential output missing range proof")]
    MissingRangeProof,
    #[error("confidential output has non-zero value (must be 0)")]
    InvalidConfidentialValue,
    #[error("invalid range proof")]
    InvalidRangeProof,
    #[error("commitment balance check failed (inflation detected)")]
    UnbalancedCommitments,
    #[error("too many range proofs: {got}, max allowed: {max}")]
    TooManyProofs { got: usize, max: usize },
}

/// Backend interface used by the ledger applicator.
pub trait UtxoBackend {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError>;
    fn insert(&mut self, outpoint: OutPoint, record: OutputRecord) -> Result<(), UtxoError>;
    fn remove(&mut self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError>;
    fn contains_link_tag(&self, tag: &[u8; 32]) -> Result<bool, UtxoError>;
    fn record_link_tag(&mut self, tag: [u8; 32]) -> Result<(), UtxoError>;
    fn remove_link_tag(&mut self, tag: &[u8; 32]) -> Result<(), UtxoError>;
    fn allocate_compact_index(&mut self) -> Result<u64, UtxoError>;
}

/// Simple in-memory backend used for tests and prototypes.
#[derive(Debug, Default)]
pub struct MemoryUtxoStore {
    utxos: BTreeMap<OutPoint, OutputRecord>,
    seen_tags: HashSet<[u8; 32]>,
    next_compact: u64,
}

impl MemoryUtxoStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }
}

impl UtxoBackend for MemoryUtxoStore {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError> {
        Ok(self.utxos.get(outpoint).cloned())
    }

    fn insert(&mut self, outpoint: OutPoint, record: OutputRecord) -> Result<(), UtxoError> {
        self.utxos.insert(outpoint, record);
        Ok(())
    }

    fn remove(&mut self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError> {
        Ok(self.utxos.remove(outpoint))
    }

    fn contains_link_tag(&self, tag: &[u8; 32]) -> Result<bool, UtxoError> {
        Ok(self.seen_tags.contains(tag))
    }

    fn record_link_tag(&mut self, tag: [u8; 32]) -> Result<(), UtxoError> {
        self.seen_tags.insert(tag);
        Ok(())
    }

    fn remove_link_tag(&mut self, tag: &[u8; 32]) -> Result<(), UtxoError> {
        self.seen_tags.remove(tag);
        Ok(())
    }

    fn allocate_compact_index(&mut self) -> Result<u64, UtxoError> {
        let index = self.next_compact;
        self.next_compact = self.next_compact.saturating_add(1);
        Ok(index)
    }
}

/// Captures the information necessary to revert a block application.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockUndo {
    spent: Vec<(OutPoint, OutputRecord)>,
}

impl BlockUndo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_spent(&mut self, outpoint: OutPoint, record: OutputRecord) {
        self.spent.push((outpoint, record));
    }

    pub fn spent(&self) -> &[(OutPoint, OutputRecord)] {
        &self.spent
    }
}

/// Apply a fully validated block to the UTXO set.
///
/// # Metrics
/// Optional `metrics_fn` callback for recording privacy validation metrics.
/// Called with ("verify_success", duration_ms), ("invalid_proof", 0), or ("balance_failure", 0).
pub fn apply_block<B: UtxoBackend, F>(
    store: &mut B,
    block: &Block,
    height: u64,
    metrics_fn: Option<F>,
) -> Result<BlockUndo, UtxoError>
where
    F: FnMut(&str, u64) + Clone,
{
    if block.txs.is_empty() {
        return Err(UtxoError::EmptyBlock);
    }

    let mut consumed: Vec<OutPoint> = Vec::new();
    let mut seen_outpoints: HashSet<OutPoint> = HashSet::new();
    let mut new_tags: Vec<[u8; 32]> = Vec::new();
    let mut block_tags: HashSet<[u8; 32]> = HashSet::new();
    let mut produced: Vec<(OutPoint, OutputRecord)> = Vec::new();
    let mut undo = BlockUndo::new();

    for (tx_index, tx) in block.txs.iter().enumerate() {
        let binding = tx::binding_hash(&tx.outputs, &tx.witness);

        // Validate confidential transaction rules (if any confidential outputs present)
        validate_confidential_tx(store, tx, metrics_fn.clone())?;

        if tx_index == 0 {
            if !tx.inputs.is_empty() {
                return Err(UtxoError::InvalidCoinbase);
            }
        } else {
            consume_inputs(
                store,
                tx,
                &binding,
                &mut consumed,
                &mut seen_outpoints,
                &mut block_tags,
                &mut new_tags,
            )?;
        }
        collect_outputs(store, tx, height, &mut produced)?;
    }

    for tag in new_tags {
        store.record_link_tag(tag)?;
    }

    for outpoint in &consumed {
        let removed = store
            .remove(outpoint)?
            .ok_or(UtxoError::MissingOutPoint(*outpoint))?;
        undo.push_spent(*outpoint, removed);
    }

    for (outpoint, record) in produced {
        store.insert(outpoint, record)?;
    }

    Ok(undo)
}

/// Validate confidential transaction privacy rules.
///
/// Checks:
/// 1. Confidential outputs have value = 0
/// 2. Each confidential output has a corresponding range proof
/// 3. Range proofs are valid
/// 4. Commitments balance (inputs - outputs = 0)
/// 5. DoS protection: max proofs per transaction
///
/// # Metrics
/// If `record_metrics` callback is provided, it will be called with:
/// - `("verify_success", duration_ms)` for each successful verification
/// - `("invalid_proof", 0)` for each invalid proof
/// - `("balance_failure", 0)` for commitment balance failures
fn validate_confidential_tx<B: UtxoBackend, F>(
    store: &B,
    tx: &Tx,
    mut record_metrics: Option<F>,
) -> Result<(), UtxoError>
where
    F: FnMut(&str, u64),
{
    // Count confidential outputs and collect commitments
    let mut confidential_outputs = Vec::new();
    let mut output_commitments = Vec::new();

    for (idx, output) in tx.outputs.iter().enumerate() {
        if let Some(ref commitment) = output.commitment {
            // Rule 1: Confidential output must have value = 0
            if output.value != 0 {
                return Err(UtxoError::InvalidConfidentialValue);
            }
            confidential_outputs.push(idx);
            output_commitments.push(commitment.clone());
        }
    }

    // If no confidential outputs, skip privacy checks
    if confidential_outputs.is_empty() {
        return Ok(());
    }

    // Rule 2: Check we have enough range proofs
    if tx.witness.range_proofs.len() < confidential_outputs.len() {
        return Err(UtxoError::MissingRangeProof);
    }

    // DoS protection: max proofs per transaction
    let max_proofs = get_max_proofs_per_block();
    if tx.witness.range_proofs.len() > max_proofs {
        return Err(UtxoError::TooManyProofs {
            got: tx.witness.range_proofs.len(),
            max: max_proofs,
        });
    }

    // Rule 3: Verify range proofs
    for (i, &output_idx) in confidential_outputs.iter().enumerate() {
        let output = &tx.outputs[output_idx];
        let commitment = output.commitment.as_ref().unwrap(); // Safe: we checked above
        let proof = &tx.witness.range_proofs[i];

        // Measure verification latency
        let start = std::time::Instant::now();
        let valid = verify_range(commitment, proof);
        let duration_ms = start.elapsed().as_millis() as u64;

        if !valid {
            if let Some(ref mut metrics_fn) = record_metrics {
                metrics_fn("invalid_proof", 0);
            }
            return Err(UtxoError::InvalidRangeProof);
        }

        if let Some(ref mut metrics_fn) = record_metrics {
            metrics_fn("verify_success", duration_ms);
        }
    }

    // Rule 4: Verify commitment balance (inflation check)
    // Collect input commitments from UTXOs
    let mut input_commitments = Vec::new();
    for input in &tx.inputs {
        let outpoint = OutPoint::new(input.prev_txid, input.prev_index);
        if let Some(record) = store.get(&outpoint)?
            && let Some(ref commitment) = record.output.commitment
        {
            input_commitments.push(commitment.clone());
        }
    }

    // Only check balance if we have both input and output commitments
    if (!input_commitments.is_empty() || !output_commitments.is_empty())
        && !balance_commitments(&input_commitments, &output_commitments)
    {
        if let Some(ref mut metrics_fn) = record_metrics {
            metrics_fn("balance_failure", 0);
        }
        return Err(UtxoError::UnbalancedCommitments);
    }

    Ok(())
}

fn consume_inputs<B: UtxoBackend>(
    store: &mut B,
    tx: &Tx,
    binding_hash: &[u8; 32],
    consumed: &mut Vec<OutPoint>,
    seen_outpoints: &mut HashSet<OutPoint>,
    block_tags: &mut HashSet<[u8; 32]>,
    new_tags: &mut Vec<[u8; 32]>,
) -> Result<(), UtxoError> {
    // ==== PHASE 1: Pre-validation (non-cryptographic checks) ====
    // Validate all inputs before expensive signature verification
    for input in &tx.inputs {
        if input.one_of_many_proof.is_empty() {
            return Err(UtxoError::InvalidProof);
        }
        let outpoint = OutPoint::new(input.prev_txid, input.prev_index);
        if !seen_outpoints.insert(outpoint) {
            return Err(UtxoError::DuplicateOutPoint);
        }
        if !block_tags.insert(input.ann_link_tag) {
            return Err(UtxoError::DuplicateLinkTag(input.ann_link_tag));
        }
        if store.contains_link_tag(&input.ann_link_tag)? {
            return Err(UtxoError::DuplicateLinkTag(input.ann_link_tag));
        }
        // Ensure the output exists before committing to remove it later.
        if store.get(&outpoint)?.is_none() {
            return Err(UtxoError::MissingOutPoint(outpoint));
        }
    }

    // ==== PHASE 2: Batch signature verification (cryptographic) ====
    // Collect all messages for batch verification (if multiple inputs)
    if tx.inputs.len() > 1 {
        // Batch path: collect all messages and verify in parallel
        let mut messages = Vec::with_capacity(tx.inputs.len());
        let mut verify_items = Vec::with_capacity(tx.inputs.len());

        // Compute messages for all inputs
        for input in &tx.inputs {
            let message = tx::input_auth_message(input, binding_hash);
            messages.push(message);
        }

        // Create VerifyItems
        for (i, input) in tx.inputs.iter().enumerate() {
            let item = VerifyItem::new(
                crypto::context::TX,
                input.pq_signature.alg,
                input.spend_public.as_bytes(),
                &messages[i],
                &input.pq_signature.bytes,
            )
            .map_err(|_| UtxoError::InvalidSignature)?;
            verify_items.push(item);
        }

        // Batch verify all signatures
        let outcome = crypto::batch_verify_v2(verify_items);
        if !outcome.is_all_valid() {
            return Err(UtxoError::InvalidSignature);
        }
    } else if tx.inputs.len() == 1 {
        // Single input: use regular verify (no batch overhead)
        let input = &tx.inputs[0];
        let message = tx::input_auth_message(input, binding_hash);
        crypto::verify(
            &message,
            &input.spend_public,
            &input.pq_signature,
            crypto::context::TX,
        )
        .map_err(|_| UtxoError::InvalidSignature)?;
    }
    // else: no inputs, nothing to verify

    // ==== PHASE 3: Record consumed outputs and link tags ====
    for input in &tx.inputs {
        let outpoint = OutPoint::new(input.prev_txid, input.prev_index);
        consumed.push(outpoint);
        new_tags.push(input.ann_link_tag);
    }

    Ok(())
}

fn collect_outputs<B: UtxoBackend>(
    store: &mut B,
    tx: &Tx,
    height: u64,
    produced: &mut Vec<(OutPoint, OutputRecord)>,
) -> Result<(), UtxoError> {
    let txid = tx.txid();
    for (index, output) in tx.outputs.iter().cloned().enumerate() {
        let outpoint = OutPoint::new(*txid.as_bytes(), index as u32);
        let compact_index = store.allocate_compact_index()?;
        let record = OutputRecord::new(output, height, compact_index);
        produced.push((outpoint, record));
    }
    Ok(())
}

/// Revert the effects of a block using the supplied undo data.
pub fn undo_block<B: UtxoBackend>(
    store: &mut B,
    block: &Block,
    undo: &BlockUndo,
) -> Result<(), UtxoError> {
    if block.txs.is_empty() {
        return Err(UtxoError::EmptyBlock);
    }

    // Remove outputs created by the block in reverse order.
    for tx in block.txs.iter().rev() {
        let txid = tx.txid();
        for (index, _) in tx.outputs.iter().enumerate().rev() {
            let outpoint = OutPoint::new(*txid.as_bytes(), index as u32);
            store
                .remove(&outpoint)?
                .ok_or(UtxoError::MissingOutPoint(outpoint))?;
        }
    }

    // Remove linkability tags introduced by the block.
    for tx in block.txs.iter().skip(1) {
        for input in &tx.inputs {
            store.remove_link_tag(&input.ann_link_tag)?;
        }
    }

    // Reinsert previously spent outputs.
    for (outpoint, record) in undo.spent().iter().rev() {
        store.insert(*outpoint, record.clone())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{Block, BlockHeader};
    use crypto::KeyMaterial;
    use tx::{self, OutputMeta, TxBuilder, Witness, binding_hash, build_signed_input};

    fn dummy_block_header(prev: [u8; 32]) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: prev,
            merkle_root: [0u8; 32],
            utxo_root: [0u8; 32],
            time: 0,
            n_bits: 0,
            nonce: 0,
            alg_tag: 1,
        }
    }

    fn coinbase(amount: u64) -> Tx {
        let km = KeyMaterial::random();
        let scan = km.derive_scan_keypair(0);
        let spend = km.derive_spend_keypair(0);
        let stealth = tx::build_stealth_blob(&scan.public, &spend.public, &amount.to_le_bytes());
        TxBuilder::new()
            .add_output(Output::new(
                stealth,
                amount,
                OutputMeta {
                    deposit_flag: false,
                    deposit_id: None,
                },
            ))
            .set_witness(Witness {
                range_proofs: Vec::new(),
                stamp: 0,
                extra: Vec::new(),
            })
            .build()
    }

    fn assemble_block(txs: Vec<Tx>) -> Block {
        Block {
            header: dummy_block_header([0u8; 32]),
            txs,
        }
    }

    #[test]
    fn coinbase_adds_utxo() {
        let mut store = MemoryUtxoStore::new();
        let block = assemble_block(vec![coinbase(50)]);
        let undo = apply_block(&mut store, &block, 1, None::<fn(&str, u64)>).expect("apply block");
        assert_eq!(store.utxo_count(), 1);
        assert!(undo.spent().is_empty());
    }

    #[test]
    fn duplicate_outpoint_within_block_is_rejected() {
        let mut store = MemoryUtxoStore::new();
        let spend = KeyMaterial::random().derive_spend_keypair(0);
        let txid = [11u8; 32];
        let outpoint = OutPoint::new(txid, 0);
        let output = tx::Output::new(vec![1], 1000u64, OutputMeta::default());
        let compact = store.allocate_compact_index().unwrap();
        store
            .insert(outpoint, OutputRecord::new(output, 0, compact))
            .unwrap();

        let binding = binding_hash(&[], &Witness::default());
        let input = build_signed_input(txid, 0, &spend, vec![1], &binding);
        let tx = TxBuilder::new()
            .add_input(input.clone())
            .add_input(input)
            .build();
        let block = assemble_block(vec![coinbase(25), tx]);
        let err = apply_block(&mut store, &block, 2, None::<fn(&str, u64)>)
            .expect_err("duplicate outpoint");
        assert_eq!(err, UtxoError::DuplicateOutPoint);
    }

    #[test]
    fn double_spend_via_link_tag_is_rejected() {
        let mut store = MemoryUtxoStore::new();
        let spend = KeyMaterial::random().derive_spend_keypair(0);
        let txid = [22u8; 32];
        let outpoint = OutPoint::new(txid, 0);
        let output = tx::Output::new(vec![2], 2000u64, OutputMeta::default());
        let compact = store.allocate_compact_index().unwrap();
        store
            .insert(outpoint, OutputRecord::new(output, 0, compact))
            .unwrap();

        let binding = binding_hash(&[], &Witness::default());
        let spend_input = build_signed_input(txid, 0, &spend, vec![2], &binding);
        let spend = TxBuilder::new().add_input(spend_input.clone()).build();
        let _ = apply_block(
            &mut store,
            &assemble_block(vec![coinbase(1), spend.clone()]),
            2,
            None::<fn(&str, u64)>,
        )
        .unwrap();

        let err = apply_block(
            &mut store,
            &assemble_block(vec![coinbase(1), spend]),
            3,
            None::<fn(&str, u64)>,
        )
        .unwrap_err();
        assert_eq!(err, UtxoError::DuplicateLinkTag(spend_input.ann_link_tag));
    }

    #[test]
    fn missing_outpoint_is_detected() {
        let mut store = MemoryUtxoStore::new();
        let spend = KeyMaterial::random().derive_spend_keypair(0);
        let binding = binding_hash(&[], &Witness::default());
        let bogus = build_signed_input([9u8; 32], 0, &spend, vec![3], &binding);
        let spend = TxBuilder::new().add_input(bogus).build();
        let block = assemble_block(vec![coinbase(1), spend]);
        let err = apply_block(&mut store, &block, 1, None::<fn(&str, u64)>).unwrap_err();
        assert!(matches!(err, UtxoError::MissingOutPoint(_)));
    }

    #[test]
    fn undo_restores_previous_state() {
        let mut store = MemoryUtxoStore::new();
        let material = KeyMaterial::random();
        let scan = material.derive_scan_keypair(0);
        let spend = material.derive_spend_keypair(0);
        let stealth = tx::build_stealth_blob(&scan.public, &spend.public, b"coinbase");
        let coinbase_tx = TxBuilder::new()
            .add_output(Output::new(
                stealth,
                5000u64,
                OutputMeta {
                    deposit_flag: false,
                    deposit_id: None,
                },
            ))
            .set_witness(Witness::default())
            .build();
        let coin_block = assemble_block(vec![coinbase_tx.clone()]);
        let _ =
            apply_block(&mut store, &coin_block, 1, None::<fn(&str, u64)>).expect("apply coinbase");

        let coin_out = OutPoint::new(*coinbase_tx.txid().as_bytes(), 0);
        assert!(store.get(&coin_out).unwrap().is_some());

        let spend_output = Output::new(vec![9], 3000u64, OutputMeta::default());
        let witness = Witness::default();
        let binding = binding_hash(std::slice::from_ref(&spend_output), &witness);
        let spend_input = build_signed_input(
            *coinbase_tx.txid().as_bytes(),
            0,
            &spend,
            vec![1, 2, 3],
            &binding,
        );
        let spend_tx = TxBuilder::new()
            .add_input(spend_input.clone())
            .add_output(spend_output)
            .set_witness(witness)
            .build();
        let block = assemble_block(vec![coinbase(1), spend_tx]);

        let undo = apply_block(&mut store, &block, 2, None::<fn(&str, u64)>).expect("apply block");
        assert!(store.get(&coin_out).unwrap().is_none());

        undo_block(&mut store, &block, &undo).expect("undo block");
        let restored = store.get(&coin_out).unwrap();
        assert!(restored.is_some());
    }
}
