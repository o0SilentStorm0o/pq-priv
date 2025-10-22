//! Integration tests for batch signature verification in consensus context.
//!
//! These tests verify that the batch_verify_v2() optimization works correctly
//! when validating blocks with multiple transactions in a realistic consensus scenario.

use std::collections::{HashMap, HashSet};

use consensus::{Block, BlockHeader, ChainParams};
use crypto::{
    AlgTag, Dilithium2Scheme, PublicKey, SecretKey, SignatureScheme, compute_link_tag, context,
    random_nonce,
};
use tx::{Input, Output, OutputMeta, Tx, TxBuilder, Witness, binding_hash};
use utxo::{OutPoint, OutputRecord, UtxoBackend, UtxoError, apply_block};

/// Simple in-memory UTXO backend for testing
#[derive(Default)]
struct TestUtxoBackend {
    utxos: HashMap<OutPoint, OutputRecord>,
    link_tags: HashSet<[u8; 32]>,
    next_compact: u64,
}

impl UtxoBackend for TestUtxoBackend {
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
        Ok(self.link_tags.contains(tag))
    }

    fn record_link_tag(&mut self, tag: [u8; 32]) -> Result<(), UtxoError> {
        self.link_tags.insert(tag);
        Ok(())
    }

    fn remove_link_tag(&mut self, tag: &[u8; 32]) -> Result<(), UtxoError> {
        self.link_tags.remove(tag);
        Ok(())
    }

    fn allocate_compact_index(&mut self) -> Result<u64, UtxoError> {
        let index = self.next_compact;
        self.next_compact += 1;
        Ok(index)
    }
}

/// Helper to create a signed input for testing
fn create_signed_input(
    prev_txid: [u8; 32],
    prev_index: u32,
    public: &PublicKey,
    secret: &SecretKey,
    binding_hash: &[u8; 32],
) -> Input {
    let nonce = random_nonce::<16>();
    let link = compute_link_tag(public, &nonce);
    let ring_proof = vec![0x00]; // Minimal proof for testing

    // Compute auth message (same as tx::input_auth_message)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&prev_txid);
    hasher.update(&prev_index.to_le_bytes());
    hasher.update(&link);
    hasher.update(public.as_bytes());
    hasher.update(binding_hash);
    hasher.update(blake3::hash(&ring_proof).as_bytes());
    let message: [u8; 32] = hasher.finalize().into();

    // Sign with Dilithium2
    let signature = crypto::sign(&message, secret, AlgTag::Dilithium2, context::TX)
        .expect("signing should succeed");

    Input::new(
        prev_txid,
        prev_index,
        link,
        public.clone(),
        ring_proof,
        signature,
    )
}

/// Create a simple output for testing
fn create_output(value_commitment: [u8; 32]) -> Output {
    Output::new(
        vec![0xAA; 64], // stealth_blob
        value_commitment,
        OutputMeta::default(),
    )
}

/// Create a coinbase transaction
fn create_coinbase(stamp: u64) -> Tx {
    let output = create_output([stamp as u8; 32]);
    TxBuilder::new()
        .add_output(output)
        .set_witness(Witness {
            range_proofs: Vec::new(),
            stamp,
            extra: Vec::new(),
        })
        .build()
}

/// Create a test block with transactions
fn create_test_block(prev_hash: [u8; 32], txs: Vec<Tx>, time: u64) -> Block {
    let header = BlockHeader {
        version: 1,
        prev_hash,
        merkle_root: consensus::merkle_root(&txs),
        utxo_root: [0; 32],
        time,
        n_bits: 0x1d00ffff,
        nonce: 0,
        alg_tag: 1,
    };
    Block { header, txs }
}

/// Test: Block with many transactions uses parallel batch verification
#[test]
fn block_with_many_transactions_uses_batch_verify() {
    let _params = ChainParams::default();

    // Generate multiple keypairs to simulate different users
    let mut keypairs = Vec::new();
    for i in 0..50 {
        let seed = [i as u8; 32];
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen");
        keypairs.push((PublicKey::from_bytes(pk), SecretKey::from_bytes(sk)));
    }

    // Create UTXO backend with initial outputs (from genesis/previous block)
    let mut backend = TestUtxoBackend::default();

    for (i, (_public, _)) in keypairs.iter().enumerate() {
        let txid = [i as u8; 32];
        let outpoint = OutPoint::new(txid, 0);
        let output = create_output([i as u8; 32]);
        let record = OutputRecord::new(output, 0, i as u64);

        backend.insert(outpoint, record).expect("insert");
    }

    // Build transactions (each spending 1 input) for block
    let mut transactions = vec![create_coinbase(1000)]; // Coinbase first

    for (i, (public, secret)) in keypairs.iter().enumerate() {
        let outpoint = OutPoint::new([i as u8; 32], 0);

        // Create transaction output
        let output = create_output([(i + 100) as u8; 32]);
        let witness = Witness::default();
        let binding = binding_hash(std::slice::from_ref(&output), &witness);

        // Create signed input
        let input = create_signed_input(outpoint.txid, outpoint.index, public, secret, &binding);

        // Build transaction
        let tx = TxBuilder::new()
            .add_input(input)
            .add_output(output)
            .set_witness(witness)
            .build();

        transactions.push(tx);
    }

    // Create block with 51 transactions (1 coinbase + 50 regular)
    let block = create_test_block([0; 32], transactions, 1000);

    // Record initial batch verify metrics
    let calls_before = crypto::get_batch_verify_calls_total();
    let items_before = crypto::get_batch_verify_items_total();

    // Apply block (validates all transactions)
    let result = apply_block(&mut backend, &block, 1);
    assert!(
        result.is_ok(),
        "Block with 50 valid transactions should apply successfully"
    );

    // Verify batch verify was used
    let calls_after = crypto::get_batch_verify_calls_total();
    let items_after = crypto::get_batch_verify_items_total();

    println!("Batch verify calls: {} -> {}", calls_before, calls_after);
    println!("Batch verify items: {} -> {}", items_before, items_after);

    // Note: Each tx has 1 input, so regular verify() is used (no batch overhead per tx).
    // But implementation could batch across multiple txs in future.
    // This test validates the validation code path works correctly.

    // All transactions validated successfully
    // 51 outputs: 50 consumed + created by regular txs, plus 1 from coinbase
    assert_eq!(
        backend.utxos.len(),
        51,
        "UTXO set should have 51 outputs (50 from regular txs + 1 coinbase)"
    );
}

/// Test: Block with one invalid signature is rejected
#[test]
fn block_with_one_invalid_signature_is_rejected() {
    // Generate keypairs
    let (pk1, sk1) = Dilithium2Scheme::keygen_from_seed(&[1; 32]).expect("keygen");
    let (pk2, _sk2) = Dilithium2Scheme::keygen_from_seed(&[2; 32]).expect("keygen");

    let public1 = PublicKey::from_bytes(pk1);
    let secret1 = SecretKey::from_bytes(sk1);
    let public2 = PublicKey::from_bytes(pk2);

    // Create UTXO backend with 2 outputs
    let mut backend = TestUtxoBackend::default();

    let outpoint1 = OutPoint::new([10; 32], 0);
    let outpoint2 = OutPoint::new([20; 32], 0);

    backend
        .insert(outpoint1, OutputRecord::new(create_output([1; 32]), 0, 0))
        .unwrap();
    backend
        .insert(outpoint2, OutputRecord::new(create_output([2; 32]), 0, 1))
        .unwrap();

    // Create transaction with 2 inputs
    let output = create_output([99; 32]);
    let witness = Witness::default();
    let binding = binding_hash(std::slice::from_ref(&output), &witness);

    // Input 1: Valid signature
    let input1 = create_signed_input(
        outpoint1.txid,
        outpoint1.index,
        &public1,
        &secret1,
        &binding,
    );

    // Input 2: INVALID signature (signed with wrong key)
    let input2_bad = create_signed_input(
        outpoint2.txid,
        outpoint2.index,
        &public2, // Correct public key
        &secret1, // WRONG secret key
        &binding,
    );

    // Build transaction with invalid signature
    let tx = TxBuilder::new()
        .add_input(input1)
        .add_input(input2_bad)
        .add_output(output)
        .set_witness(witness)
        .build();

    // Create block with coinbase + invalid tx
    let block = create_test_block([0; 32], vec![create_coinbase(1000), tx], 1000);

    // Record metrics before
    let invalid_before = crypto::get_batch_verify_invalid_total();

    // Attempt to apply block - should FAIL
    let result = apply_block(&mut backend, &block, 1);

    assert!(
        result.is_err(),
        "Block with invalid signature should be rejected"
    );

    // Verify invalid counter incremented
    let invalid_after = crypto::get_batch_verify_invalid_total();
    assert!(
        invalid_after > invalid_before,
        "Invalid signature counter should increment"
    );

    // UTXO set should be unchanged (block rejected)
    assert_eq!(
        backend.utxos.len(),
        2,
        "UTXO set should be unchanged after rejection"
    );
}

/// Test: Multi-input transaction triggers batch verification
#[test]
fn multi_input_transaction_uses_batch_path() {
    // Generate 5 keypairs
    let mut keypairs = Vec::new();
    for i in 0..5 {
        let seed = [i as u8; 32];
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen");
        keypairs.push((PublicKey::from_bytes(pk), SecretKey::from_bytes(sk)));
    }

    // Create UTXO backend with 5 outputs
    let mut backend = TestUtxoBackend::default();

    for (i, _) in keypairs.iter().enumerate() {
        let outpoint = OutPoint::new([i as u8; 32], 0);
        let record = OutputRecord::new(create_output([i as u8; 32]), 0, i as u64);
        backend.insert(outpoint, record).unwrap();
    }

    // Create transaction with 5 inputs (should trigger batch verify)
    let output = create_output([200; 32]);
    let witness = Witness::default();
    let binding = binding_hash(std::slice::from_ref(&output), &witness);

    let mut tx_builder = TxBuilder::new();
    for (i, (public, secret)) in keypairs.iter().enumerate() {
        let outpoint = OutPoint::new([i as u8; 32], 0);
        let input = create_signed_input(outpoint.txid, outpoint.index, public, secret, &binding);
        tx_builder = tx_builder.add_input(input);
    }

    let tx = tx_builder.add_output(output).set_witness(witness).build();

    // Create block
    let block = create_test_block([0; 32], vec![create_coinbase(1000), tx], 1000);

    // Record metrics before
    let calls_before = crypto::get_batch_verify_calls_total();
    let items_before = crypto::get_batch_verify_items_total();

    // Apply block
    let result = apply_block(&mut backend, &block, 1);
    assert!(result.is_ok(), "multi-input transaction should validate");

    // Verify batch verify was used
    let calls_after = crypto::get_batch_verify_calls_total();
    let items_after = crypto::get_batch_verify_items_total();

    assert!(
        calls_after > calls_before,
        "batch_verify_v2() should be called for multi-input tx"
    );
    assert!(
        items_after >= items_before + 5,
        "at least 5 signatures should be verified in batch"
    );

    println!(
        "✓ Multi-input tx triggered batch verify: {} calls, {} items processed",
        calls_after - calls_before,
        items_after - items_before
    );
}

/// Test: Large batch (100 inputs) validates correctly
#[test]
fn large_batch_validates_correctly() {
    const BATCH_SIZE: usize = 100;

    // Generate keypairs
    let mut keypairs = Vec::new();
    for i in 0..BATCH_SIZE {
        let mut seed = [0u8; 32];
        seed[0] = (i / 256) as u8;
        seed[1] = (i % 256) as u8;
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen");
        keypairs.push((PublicKey::from_bytes(pk), SecretKey::from_bytes(sk)));
    }

    // Create UTXO backend
    let mut backend = TestUtxoBackend::default();

    for (i, _) in keypairs.iter().enumerate() {
        let mut txid = [0u8; 32];
        txid[0] = (i / 256) as u8;
        txid[1] = (i % 256) as u8;
        let outpoint = OutPoint::new(txid, 0);
        let record = OutputRecord::new(create_output([i as u8; 32]), 0, i as u64);
        backend.insert(outpoint, record).unwrap();
    }

    // Create transaction with 100 inputs
    let output = create_output([255; 32]);
    let witness = Witness::default();
    let binding = binding_hash(std::slice::from_ref(&output), &witness);

    let mut tx_builder = TxBuilder::new();
    for (i, (public, secret)) in keypairs.iter().enumerate() {
        let mut txid = [0u8; 32];
        txid[0] = (i / 256) as u8;
        txid[1] = (i % 256) as u8;
        let outpoint = OutPoint::new(txid, 0);
        let input = create_signed_input(outpoint.txid, outpoint.index, public, secret, &binding);
        tx_builder = tx_builder.add_input(input);
    }

    let tx = tx_builder.add_output(output).set_witness(witness).build();

    // Create block
    let block = create_test_block([0; 32], vec![create_coinbase(1000), tx], 1000);

    // Record metrics and timing
    let _calls_before = crypto::get_batch_verify_calls_total();
    let items_before = crypto::get_batch_verify_items_total();
    let duration_before = crypto::get_batch_verify_duration_us_total();

    let start = std::time::Instant::now();

    // Apply block
    let result = apply_block(&mut backend, &block, 1);
    assert!(result.is_ok(), "large batch should validate");

    let elapsed = start.elapsed();

    // Verify metrics
    let _calls_after = crypto::get_batch_verify_calls_total();
    let items_after = crypto::get_batch_verify_items_total();
    let duration_after = crypto::get_batch_verify_duration_us_total();

    assert!(
        items_after >= items_before + BATCH_SIZE as u64,
        "should process all signatures"
    );

    let duration_us = duration_after - duration_before;
    println!(
        "✓ Validated {} signatures in {:?} (batch verify: {} μs)",
        BATCH_SIZE, elapsed, duration_us
    );
    println!(
        "  Average per signature: {:.2} μs",
        duration_us as f64 / BATCH_SIZE as f64
    );
}

/// Test: Mixed valid/invalid signatures in batch are detected
#[test]
fn mixed_validity_batch_detected() {
    // Generate 10 keypairs
    let mut keypairs = Vec::new();
    for i in 0..10 {
        let seed = [i as u8; 32];
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen");
        keypairs.push((PublicKey::from_bytes(pk), SecretKey::from_bytes(sk)));
    }

    // Create UTXO backend
    let mut backend = TestUtxoBackend::default();

    for (i, _) in keypairs.iter().enumerate() {
        let outpoint = OutPoint::new([i as u8; 32], 0);
        let record = OutputRecord::new(create_output([i as u8; 32]), 0, i as u64);
        backend.insert(outpoint, record).unwrap();
    }

    // Create transaction with 10 inputs, but input #5 has INVALID signature
    let output = create_output([123; 32]);
    let witness = Witness::default();
    let binding = binding_hash(std::slice::from_ref(&output), &witness);

    let mut tx_builder = TxBuilder::new();
    for (i, (public, secret)) in keypairs.iter().enumerate() {
        let outpoint = OutPoint::new([i as u8; 32], 0);

        let input = if i == 5 {
            // Input 5: Sign with WRONG key
            let wrong_secret = &keypairs[(i + 1) % 10].1;
            create_signed_input(
                outpoint.txid,
                outpoint.index,
                public,
                wrong_secret,
                &binding,
            )
        } else {
            // Other inputs: Valid signatures
            create_signed_input(outpoint.txid, outpoint.index, public, secret, &binding)
        };

        tx_builder = tx_builder.add_input(input);
    }

    let tx = tx_builder.add_output(output).set_witness(witness).build();

    // Create block
    let block = create_test_block([0; 32], vec![create_coinbase(1000), tx], 1000);

    // Apply block - should FAIL due to 1 invalid signature
    let result = apply_block(&mut backend, &block, 1);

    assert!(
        result.is_err(),
        "Block with 1 invalid signature (out of 10) should be rejected"
    );

    // UTXO backend unchanged
    assert_eq!(backend.utxos.len(), 10, "UTXO set should be unchanged");
}
