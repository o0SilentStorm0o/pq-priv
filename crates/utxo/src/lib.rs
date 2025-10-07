//! In-memory UTXO management primitives supporting double-spend detection.

use std::collections::{BTreeMap, HashSet};

use consensus::Block;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tx::{Output, Tx};

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
}

/// Backend interface used by the ledger applicator.
pub trait UtxoBackend {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError>;
    fn insert(&mut self, outpoint: OutPoint, record: OutputRecord) -> Result<(), UtxoError>;
    fn remove(&mut self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError>;
    fn contains_link_tag(&self, tag: &[u8; 32]) -> Result<bool, UtxoError>;
    fn record_link_tag(&mut self, tag: [u8; 32]) -> Result<(), UtxoError>;
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

    fn allocate_compact_index(&mut self) -> Result<u64, UtxoError> {
        let index = self.next_compact;
        self.next_compact = self.next_compact.saturating_add(1);
        Ok(index)
    }
}

/// Apply a fully validated block to the UTXO set.
pub fn apply_block<B: UtxoBackend>(
    store: &mut B,
    block: &Block,
    height: u64,
) -> Result<(), UtxoError> {
    if block.txs.is_empty() {
        return Err(UtxoError::EmptyBlock);
    }

    let mut consumed: Vec<OutPoint> = Vec::new();
    let mut seen_outpoints: HashSet<OutPoint> = HashSet::new();
    let mut new_tags: Vec<[u8; 32]> = Vec::new();
    let mut block_tags: HashSet<[u8; 32]> = HashSet::new();
    let mut produced: Vec<(OutPoint, OutputRecord)> = Vec::new();

    for (tx_index, tx) in block.txs.iter().enumerate() {
        if tx_index == 0 {
            if !tx.inputs.is_empty() {
                return Err(UtxoError::InvalidCoinbase);
            }
        } else {
            consume_inputs(
                store,
                tx,
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
            .ok_or_else(|| UtxoError::MissingOutPoint(*outpoint))?;
        drop(removed);
    }

    for (outpoint, record) in produced {
        store.insert(outpoint, record)?;
    }

    Ok(())
}

fn consume_inputs<B: UtxoBackend>(
    store: &mut B,
    tx: &Tx,
    consumed: &mut Vec<OutPoint>,
    seen_outpoints: &mut HashSet<OutPoint>,
    block_tags: &mut HashSet<[u8; 32]>,
    new_tags: &mut Vec<[u8; 32]>,
) -> Result<(), UtxoError> {
    for input in &tx.inputs {
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

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{Block, BlockHeader};
    use crypto::{AlgTag, KeyMaterial, Signature};
    use rand::Rng;
    use tx::{Input, OutputMeta, TxBuilder, Witness};

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
        let commitment = crypto::commitment(amount, &amount.to_le_bytes());
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
        apply_block(&mut store, &block, 1).expect("apply block");
        assert_eq!(store.utxo_count(), 1);
    }

    #[test]
    fn duplicate_outpoint_within_block_is_rejected() {
        let mut store = MemoryUtxoStore::new();
        let cb = coinbase(25);
        let block = assemble_block(vec![cb.clone()]);
        apply_block(&mut store, &block, 1).expect("apply genesis");

        let outpoint = OutPoint::new(*cb.txid().as_bytes(), 0);
        let mut input_tag = [0u8; 32];
        rand::thread_rng().fill(&mut input_tag);
        let input = Input::new(
            outpoint.txid,
            outpoint.index,
            input_tag,
            Vec::new(),
            Signature::new(AlgTag::Dilithium, vec![0; 32]),
        );
        let tx = TxBuilder::new()
            .add_input(input.clone())
            .add_input(input)
            .build();
        let block = assemble_block(vec![coinbase(25), tx]);
        let err = apply_block(&mut store, &block, 2).expect_err("duplicate outpoint");
        assert_eq!(err, UtxoError::DuplicateOutPoint);
    }

    #[test]
    fn double_spend_via_link_tag_is_rejected() {
        let mut store = MemoryUtxoStore::new();
        let cb = coinbase(30);
        apply_block(&mut store, &assemble_block(vec![cb.clone()]), 1).unwrap();

        let outpoint = OutPoint::new(*cb.txid().as_bytes(), 0);
        let tag = [1u8; 32];
        let input = Input::new(
            outpoint.txid,
            outpoint.index,
            tag,
            Vec::new(),
            Signature::new(AlgTag::Dilithium, vec![0; 32]),
        );
        let spend = TxBuilder::new().add_input(input).build();
        apply_block(
            &mut store,
            &assemble_block(vec![coinbase(1), spend.clone()]),
            2,
        )
        .unwrap();

        let err =
            apply_block(&mut store, &assemble_block(vec![coinbase(1), spend]), 3).unwrap_err();
        assert_eq!(err, UtxoError::DuplicateLinkTag(tag));
    }

    #[test]
    fn missing_outpoint_is_detected() {
        let mut store = MemoryUtxoStore::new();
        let bogus = Input::new(
            [9u8; 32],
            0,
            [0u8; 32],
            Vec::new(),
            Signature::new(AlgTag::Dilithium, vec![0; 32]),
        );
        let spend = TxBuilder::new().add_input(bogus).build();
        let block = assemble_block(vec![coinbase(1), spend]);
        let err = apply_block(&mut store, &block, 1).unwrap_err();
        assert!(matches!(err, UtxoError::MissingOutPoint(_)));
    }
}
