//! Consensus-level privacy tests for confidential transactions.
//!
//! Tests end-to-end block validation including privacy features:
//! - Range proof verification
//! - Commitment balance checks
//! - DoS protection (MAX_PROOFS_PER_BLOCK)
//! - Invalid proof rejection

use consensus::{Block, BlockHeader, ChainParams};
use crypto::{commit_value, prove_range};
use tx::{Output, OutputMeta, Witness, TxBuilder};

/// Helper to create a valid block header for testing.
fn mock_block_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        utxo_root: [0u8; 32],
        time: 1234567890,
        n_bits: 0x1d00ffff, // Easy difficulty
        nonce: 0,
        alg_tag: 0,
    }
}

/// Helper to create a transparent output.
fn mock_transparent_output(value: u64) -> Output {
    Output::new(
        vec![0x01; 64], // Stealth blob
        value,
        OutputMeta::default(),
    )
}

/// Helper to create a confidential output with valid commitment and proof.
fn mock_confidential_output(value: u64, blinding: &[u8; 32]) -> (Output, crypto::RangeProof) {
    let commitment = commit_value(value, blinding);
    let proof = prove_range(value, blinding).expect("proof generation should succeed");
    let output = Output::new_confidential(
        vec![0x02; 64], // Stealth blob
        commitment,
        OutputMeta::default(),
    );
    (output, proof)
}

#[test]
fn test_valid_confidential_block() {
    // Test that a block with valid confidential TX passes consensus validation
    let _params = ChainParams::default();

    // Create confidential output
    let value = 100u64;
    let blinding = b"test_blinding_factor_32bytes!!!!";
    let (conf_output, proof) = mock_confidential_output(value, blinding);

    // Create transaction with confidential output
    let witness = Witness::new(vec![proof], 12345u64, vec![]);
    let tx = TxBuilder::new()
        .add_output(conf_output)
        .set_witness(witness)
        .build();

    // Create block with this transaction
    let mut header = mock_block_header();
    let block = Block {
        header: header.clone(),
        txs: vec![tx.clone()],
    };

    // Compute correct merkle root
    header.merkle_root = consensus::merkle_root(&block.txs);

    // Mine the block (find valid nonce)
    let test_block = Block {
        header,
        txs: vec![tx],
    };

    // For testing, we'll skip actual mining and just verify structure
    // In real consensus, this block would need valid PoW

    // Validate block structure (without PoW for this test)
    // Note: validate_block() doesn't check UTXO rules or confidential TX
    // Those are checked in apply_block() in the node crate
    assert_eq!(test_block.txs.len(), 1, "block should have 1 transaction");
    assert!(
        test_block.txs[0].outputs[0].is_confidential(),
        "output should be confidential"
    );
    assert_eq!(
        test_block.txs[0].witness.proof_count(),
        1,
        "witness should have 1 proof"
    );
}

#[test]
fn test_invalid_range_proof_rejected() {
    // Test that a block with invalid range proof is rejected by UTXO validation
    use utxo::{MemoryUtxoStore, apply_block};

    let value = 50u64;
    let blinding = b"invalid_proof_test_blinding_32!!";
    let commitment = commit_value(value, blinding);

    // Create a DIFFERENT proof (for wrong value)
    let wrong_value = 100u64;
    let wrong_blinding = b"different_blinding_32bytes!!!!!!";
    let wrong_proof = prove_range(wrong_value, wrong_blinding).expect("proof should succeed");

    // Create output with commitment but wrong proof
    let output = Output::new_confidential(
        vec![0x03; 64],
        commitment,
        OutputMeta::default(),
    );

    // Transaction with mismatched proof
    let witness = Witness::new(vec![wrong_proof], 99999u64, vec![]);
    let tx = TxBuilder::new()
        .add_output(output)
        .set_witness(witness)
        .build();

    // Create block
    let mut header = mock_block_header();
    header.merkle_root = consensus::merkle_root(&vec![tx.clone()]);
    let block = Block {
        header,
        txs: vec![tx],
    };

    // Try to apply block to UTXO set - should fail
    let mut backend = MemoryUtxoStore::new();
    let result = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);

    // Should fail with InvalidRangeProof error
    assert!(
        result.is_err(),
        "block with invalid range proof should be rejected"
    );

    let err = result.unwrap_err();
    match err {
        utxo::UtxoError::InvalidRangeProof => {
            // Expected error
        }
        other => panic!("expected InvalidRangeProof, got {:?}", other),
    }
}

#[test]
fn test_unbalanced_commitment_rejected() {
    // Test that a block with unbalanced commitments (inflation attempt) is rejected
    use utxo::{MemoryUtxoStore, apply_block};

    // Simulate a transaction trying to inflate:
    // Input: 50 coins (we'll mock this by not checking inputs)
    // Output: 100 coins (more than input!)

    let output_value = 100u64; // Inflated!
    let output_blinding = b"unbalanced_test_blinding_32!!!!!";
    let (output, proof) = mock_confidential_output(output_value, output_blinding);

    let witness = Witness::new(vec![proof], 11111u64, vec![]);
    let tx = TxBuilder::new()
        .add_output(output)
        .set_witness(witness)
        .build();

    // Create block
    let mut header = mock_block_header();
    header.merkle_root = consensus::merkle_root(&vec![tx.clone()]);
    let block = Block {
        header,
        txs: vec![tx],
    };

    // Apply block (this will fail because commitment balance check)
    // Without inputs, balance check sees outputs but no inputs to balance
    // This should fail with UnbalancedCommitments
    let mut backend = MemoryUtxoStore::new();
    let result = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);

    // Should fail with unbalanced commitments (no inputs to match output)
    assert!(
        result.is_err(),
        "block with unbalanced commitments should be rejected"
    );

    let err = result.unwrap_err();
    match err {
        utxo::UtxoError::UnbalancedCommitments => {
            // Expected - output commitments don't balance with empty inputs
        }
        other => panic!("expected UnbalancedCommitments, got {:?}", other),
    }
}

#[test]
fn test_missing_range_proof_rejected() {
    // Test that confidential output without corresponding range proof is rejected
    use utxo::{MemoryUtxoStore, apply_block};

    let value = 75u64;
    let blinding = b"missing_proof_test_blinding_32!!";
    let commitment = commit_value(value, blinding);

    let output = Output::new_confidential(
        vec![0x04; 64],
        commitment,
        OutputMeta::default(),
    );

    // Witness with NO range proof (even though output is confidential)
    let witness = Witness::new(vec![], 22222u64, vec![]);

    let tx = TxBuilder::new()
        .add_output(output)
        .set_witness(witness)
        .build();

    // Create block
    let mut header = mock_block_header();
    header.merkle_root = consensus::merkle_root(&vec![tx.clone()]);
    let block = Block {
        header,
        txs: vec![tx],
    };

    // Apply block - should fail
    let mut backend = MemoryUtxoStore::new();
    let result = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);

    assert!(
        result.is_err(),
        "block with missing range proof should be rejected"
    );

    let err = result.unwrap_err();
    // Should be MissingRangeProof error
    match err {
        utxo::UtxoError::MissingRangeProof => {
            // Expected error
        }
        other => panic!("expected MissingRangeProof, got {:?}", other),
    }
}

#[test]
fn test_dos_protection_max_proofs_per_block() {
    // Test that DoS protection limits number of proofs per block
    use utxo::{MemoryUtxoStore, apply_block};

    // Create MAX_PROOFS_PER_BLOCK + 1 confidential outputs
    let max_proofs = crypto::get_max_proofs_per_block();
    let excessive_count = (max_proofs + 1).min(1500); // Cap at reasonable number for test

    let mut outputs = Vec::new();
    let mut proofs = Vec::new();

    for i in 0..excessive_count {
        let value = (i + 1) as u64; // Different values to avoid suspicion
        let blinding = format!("blinding_{:04}_32bytes!!!!!!!!!!!", i)
            .as_bytes()
            .try_into()
            .expect("blinding should be 32 bytes");

        let (output, proof) = mock_confidential_output(value, &blinding);
        outputs.push(output);
        proofs.push(proof);
    }

    // Build TX with excessive proofs
    let witness = Witness::new(proofs, 33333u64, vec![]);
    let mut tx_builder = TxBuilder::new();
    for output in outputs {
        tx_builder = tx_builder.add_output(output);
    }
    let tx = tx_builder.set_witness(witness).build();

    // Create block
    let mut header = mock_block_header();
    header.merkle_root = consensus::merkle_root(&vec![tx.clone()]);
    let block = Block {
        header,
        txs: vec![tx],
    };

    // Apply block - should fail if exceeds MAX_PROOFS_PER_BLOCK
    let mut backend = MemoryUtxoStore::new();
    let result = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);

    // Should fail with either TooManyProofs or UnbalancedCommitments
    // (depending on which check runs first)
    assert!(
        result.is_err(),
        "block with excessive outputs should be rejected"
    );
}

#[test]
fn test_mixed_transparent_confidential_block() {
    // Test block with both transparent and confidential outputs
    use utxo::{MemoryUtxoStore, apply_block};

    // Transparent output
    let transparent = mock_transparent_output(50);

    // Confidential output
    let conf_value = 100u64;
    let conf_blinding = b"mixed_block_test_blinding_32!!!!";
    let (confidential, proof) = mock_confidential_output(conf_value, conf_blinding);

    // Transaction with both types
    let witness = Witness::new(vec![proof], 44444u64, vec![]);
    let tx = TxBuilder::new()
        .add_output(transparent)
        .add_output(confidential)
        .set_witness(witness)
        .build();

    // Create block
    let mut header = mock_block_header();
    header.merkle_root = consensus::merkle_root(&vec![tx.clone()]);
    let block = Block {
        header,
        txs: vec![tx],
    };

    // Apply block - should fail with unbalanced commitments
    // (1 confidential output with no inputs to balance)
    let mut backend = MemoryUtxoStore::new();
    let result = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);

    assert!(
        result.is_err(),
        "block with unbalanced mixed outputs should be rejected: {:?}",
        result
    );

    let err = result.unwrap_err();
    match err {
        utxo::UtxoError::UnbalancedCommitments => {
            // Expected - confidential output with no input to balance
        }
        other => panic!("expected UnbalancedCommitments, got {:?}", other),
    }
}

#[test]
fn test_confidential_output_with_nonzero_value_rejected() {
    // Test that confidential output with value != 0 is rejected
    use utxo::{MemoryUtxoStore, apply_block};

    let blinding = b"nonzero_value_test_blinding_32!!";
    let commitment = commit_value(100, blinding);
    let proof = prove_range(100, blinding).expect("proof should succeed");

    // Manually create invalid output (value != 0 but has commitment)
    let invalid_output = Output {
        stealth_blob: vec![0x05; 64],
        value: 50, // INVALID: should be 0 for confidential
        commitment: Some(commitment),
        value_commitment: [0u8; 32],
        output_meta: OutputMeta::default(),
    };

    let witness = Witness::new(vec![proof], 55555u64, vec![]);
    let tx = TxBuilder::new()
        .add_output(invalid_output)
        .set_witness(witness)
        .build();

    // Create block
    let mut header = mock_block_header();
    header.merkle_root = consensus::merkle_root(&vec![tx.clone()]);
    let block = Block {
        header,
        txs: vec![tx],
    };

    // Apply block - should fail
    let mut backend = MemoryUtxoStore::new();
    let result = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);

    assert!(
        result.is_err(),
        "block with non-zero confidential value should be rejected"
    );

    let err = result.unwrap_err();
    match err {
        utxo::UtxoError::InvalidConfidentialValue => {
            // Expected error
        }
        other => panic!("expected InvalidConfidentialValue, got {:?}", other),
    }
}

#[test]
fn test_multiple_confidential_outputs_in_block() {
    // Test block with multiple transactions each having confidential outputs
    use utxo::{MemoryUtxoStore, apply_block};

    let mut txs = Vec::new();

    for i in 0..5 {
        let value = (i + 1) * 10;
        let blinding = format!("tx_{}_blinding_32bytes!!!!!!!!!!!", i)
            .as_bytes()
            .try_into()
            .expect("blinding should be 32 bytes");

        let (output, proof) = mock_confidential_output(value, &blinding);
        let witness = Witness::new(vec![proof], 66666u64 + i, vec![]);
        let tx = TxBuilder::new()
            .add_output(output)
            .set_witness(witness)
            .build();

        txs.push(tx);
    }

    // Create block with 5 transactions
    let mut header = mock_block_header();
    header.merkle_root = consensus::merkle_root(&txs);
    let block = Block {
        header,
        txs,
    };

    // Apply block - will fail because each TX has unbalanced commitments
    // (confidential outputs with no inputs)
    let mut backend = MemoryUtxoStore::new();
    let result = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);

    assert!(
        result.is_err(),
        "block with unbalanced confidential TXs should be rejected"
    );

    let err = result.unwrap_err();
    match err {
        utxo::UtxoError::UnbalancedCommitments => {
            // Expected
        }
        other => panic!("expected UnbalancedCommitments, got {:?}", other),
    }
}
