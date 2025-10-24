//! Integration tests for confidential transaction features.
//!
//! Tests the end-to-end flow of creating, serializing, and validating
//! confidential transactions with Pedersen commitments and range proofs.

use crypto::{balance_commitments, commit_value, prove_range, verify_range};
use tx::{Output, OutputMeta, Tx, TxBuilder, Witness, binding_hash};

#[test]
fn test_create_confidential_output() {
    // Test creating a confidential output with commitment and range proof
    let value = 100u64;
    let blinding = b"output_blinding_factor_32_bytes!";

    // Generate commitment and range proof
    let commitment = commit_value(value, blinding);
    let proof = prove_range(value, blinding).expect("proof generation should succeed");

    // Verify proof matches commitment
    assert!(
        verify_range(&commitment, &proof),
        "generated proof should verify against commitment"
    );

    // Create confidential output
    let stealth_blob = vec![0x01; 64]; // Mock stealth address
    let output = Output::new_confidential(
        stealth_blob.clone(),
        commitment.clone(), // Clone commitment before moving
        OutputMeta::default(),
    );

    // Verify output properties
    assert!(output.is_confidential(), "output should be confidential");
    assert_eq!(output.value, 0, "confidential output value must be 0");
    assert!(
        output.commitment.is_some(),
        "confidential output must have commitment"
    );
    assert_eq!(
        output.stealth_blob, stealth_blob,
        "stealth blob should be preserved"
    );

    // Verify commitment content
    let stored_commitment = output.commitment.as_ref().unwrap();
    assert_eq!(
        stored_commitment.value_commit, commitment.value_commit,
        "commitment should be preserved"
    );
}

#[test]
fn test_mixed_tx_binding_hash() {
    // Test binding hash computation for transaction with mixed outputs
    let transparent_output = Output::new(
        vec![0x02; 64],
        50u64, // Transparent value
        OutputMeta::default(),
    );

    let value_conf = 75u64;
    let blinding_conf = b"confidential_blinding_32_bytes!!";
    let commitment_conf = commit_value(value_conf, blinding_conf);
    let proof_conf = prove_range(value_conf, blinding_conf).expect("proof should succeed");

    let confidential_output =
        Output::new_confidential(vec![0x03; 64], commitment_conf, OutputMeta::default());

    // Create witness with range proof for confidential output
    let witness = Witness::new(
        vec![proof_conf], // One proof for one confidential output
        12345u64,         // Timestamp
        vec![],           // No extra data
    );

    let outputs = vec![transparent_output, confidential_output];

    // Compute binding hash
    let hash1 = binding_hash(&outputs, &witness);

    // Compute again with same data - should be deterministic
    let hash2 = binding_hash(&outputs, &witness);

    assert_eq!(hash1, hash2, "binding hash should be deterministic");

    // Change one byte in witness extra - hash should change
    let witness_modified = Witness::new(
        witness.range_proofs.clone(),
        witness.stamp,
        vec![0x42], // Different extra data
    );

    let hash3 = binding_hash(&outputs, &witness_modified);

    assert_ne!(
        hash1, hash3,
        "binding hash should change when witness changes"
    );
}

#[test]
fn test_witness_range_proofs() {
    // Test witness with multiple range proofs for multiple confidential outputs
    let values = [10u64, 25u64, 50u64, 100u64];
    let blindings: Vec<&[u8; 32]> = vec![
        b"blinding_00_32bytes!!!!!!!!!!!!!",
        b"blinding_01_32bytes!!!!!!!!!!!!!",
        b"blinding_02_32bytes!!!!!!!!!!!!!",
        b"blinding_03_32bytes!!!!!!!!!!!!!",
    ];

    let mut commitments = Vec::new();
    let mut range_proofs = Vec::new();

    for (i, (&value, &blinding)) in values.iter().zip(blindings.iter()).enumerate() {
        let commitment = commit_value(value, blinding);
        let proof = prove_range(value, blinding)
            .unwrap_or_else(|e| panic!("proof {} generation failed: {:?}", i, e));

        // Verify each proof independently
        assert!(
            verify_range(&commitment, &proof),
            "proof {} should verify",
            i
        );

        commitments.push(commitment);
        range_proofs.push(proof);
    }

    // Create witness with all proofs
    let witness = Witness::new(range_proofs, 99999u64, vec![]);

    // Verify proof count
    assert_eq!(
        witness.proof_count(),
        values.len(),
        "witness should have {} proofs",
        values.len()
    );

    // Verify each proof still verifies when part of witness
    for (i, (commitment, proof)) in commitments
        .iter()
        .zip(witness.range_proofs.iter())
        .enumerate()
    {
        assert!(
            verify_range(commitment, proof),
            "proof {} should still verify in witness",
            i
        );
    }
}

#[test]
fn test_confidential_serialization() {
    // Test CBOR serialization/deserialization of confidential transaction
    use codec::{from_slice_cbor, to_vec_cbor};

    let value = 200u64;
    let blinding = b"serialization_test_blinding_32!!";
    let commitment = commit_value(value, blinding);
    let proof = prove_range(value, blinding).expect("proof should succeed");

    // Create confidential output
    let output = Output::new_confidential(
        vec![0x04; 64],
        commitment.clone(),
        OutputMeta {
            deposit_flag: true,
            deposit_id: Some([0x42; 32]),
        },
    );

    // Serialize output
    let encoded = to_vec_cbor(&output).expect("output serialization should succeed");

    // Deserialize output
    let decoded: Output = from_slice_cbor(&encoded).expect("output deserialization should succeed");

    // Verify roundtrip
    assert_eq!(output, decoded, "output should roundtrip correctly");
    assert!(
        decoded.is_confidential(),
        "decoded output should be confidential"
    );
    assert_eq!(decoded.value, 0, "decoded confidential value should be 0");

    let decoded_commitment = decoded.commitment.as_ref().unwrap();
    assert_eq!(
        decoded_commitment.value_commit, commitment.value_commit,
        "commitment should roundtrip correctly"
    );

    // Create witness with proof
    let witness = Witness::new(vec![proof.clone()], 55555u64, vec![0x01, 0x02, 0x03]);

    // Serialize witness
    let witness_encoded = to_vec_cbor(&witness).expect("witness serialization should succeed");

    // Deserialize witness
    let witness_decoded: Witness =
        from_slice_cbor(&witness_encoded).expect("witness deserialization should succeed");

    // Verify witness roundtrip
    assert_eq!(
        witness, witness_decoded,
        "witness should roundtrip correctly"
    );
    assert_eq!(
        witness_decoded.proof_count(),
        1,
        "decoded witness should have 1 proof"
    );
    assert_eq!(
        witness_decoded.stamp, 55555u64,
        "witness timestamp should roundtrip"
    );
    assert_eq!(
        witness_decoded.extra,
        vec![0x01, 0x02, 0x03],
        "witness extra data should roundtrip"
    );
}

#[test]
fn test_full_confidential_transaction() {
    // Test building a complete confidential transaction end-to-end
    use crypto::{SpendKeypair, random_nonce};

    // Create spend keypair for signing (not used in this test, just for structure)
    let seed = random_nonce::<32>();
    let _spend_keypair = SpendKeypair::from_seed(seed);

    // Create 2 confidential outputs with different values
    let value1 = 75u64;
    let value2 = 25u64;
    let blinding1 = b"output1_blinding_32bytes!!!!!!!!";
    let blinding2 = b"output2_blinding_32bytes!!!!!!!!";

    let commitment1 = commit_value(value1, blinding1);
    let commitment2 = commit_value(value2, blinding2);

    let proof1 = prove_range(value1, blinding1).expect("proof 1 should succeed");
    let proof2 = prove_range(value2, blinding2).expect("proof 2 should succeed");

    let output1 =
        Output::new_confidential(vec![0x05; 64], commitment1.clone(), OutputMeta::default());
    let output2 =
        Output::new_confidential(vec![0x06; 64], commitment2.clone(), OutputMeta::default());

    // Create witness with both proofs (in order)
    let witness = Witness::new(vec![proof1, proof2], 11111u64, vec![]);

    // Build transaction
    let tx = TxBuilder::new()
        .add_output(output1)
        .add_output(output2)
        .set_witness(witness.clone())
        .build();

    // Verify transaction structure
    assert_eq!(tx.version, 1, "version should be 1");
    assert_eq!(tx.outputs.len(), 2, "should have 2 outputs");
    assert_eq!(tx.witness.proof_count(), 2, "witness should have 2 proofs");

    // Verify all outputs are confidential
    for (i, output) in tx.outputs.iter().enumerate() {
        assert!(
            output.is_confidential(),
            "output {} should be confidential",
            i
        );
        assert_eq!(output.value, 0, "output {} value should be 0", i);
    }

    // Verify proofs still verify
    assert!(
        verify_range(&commitment1, &tx.witness.range_proofs[0]),
        "proof 1 should verify in tx"
    );
    assert!(
        verify_range(&commitment2, &tx.witness.range_proofs[1]),
        "proof 2 should verify in tx"
    );

    // Compute txid (should be deterministic)
    let txid1 = tx.txid();
    let txid2 = tx.txid();
    assert_eq!(txid1, txid2, "txid should be deterministic");

    // Compute binding hash
    let bind_hash = binding_hash(&tx.outputs, &tx.witness);
    assert_ne!(bind_hash, [0u8; 32], "binding hash should not be zero");
}

#[test]
fn test_commitment_balance_in_transaction() {
    // Test that commitments balance correctly across inputs and outputs
    // This simulates a 100 -> (60 + 40) transaction

    // Input: 100 coins (simulated as output commitment)
    let input_value = 100u64;
    let input_blinding = b"input_blinding_factor_32_bytes!!";
    let input_commitment = commit_value(input_value, input_blinding);

    // Output 1: 60 coins
    let output1_value = 60u64;
    let output1_blinding = b"output1_blinding_32bytes!!!!!!!!";
    let output1_commitment = commit_value(output1_value, output1_blinding);

    // Output 2: 40 coins
    let output2_value = 40u64;
    let output2_blinding = b"output2_blinding_32bytes!!!!!!!!";
    let output2_commitment = commit_value(output2_value, output2_blinding);

    // Verify balances: inputs == outputs (100 == 60 + 40)
    let balanced = balance_commitments(
        &[input_commitment],
        &[output1_commitment, output2_commitment],
    );

    // NOTE: This will fail unless blinding factors also balance!
    // In real usage, wallet must ensure: sum(input_blindings) == sum(output_blindings)
    // This test demonstrates the crypto primitive, not a valid transaction.
    // We expect this to fail because blindings don't balance:
    assert!(
        !balanced,
        "commitments won't balance with arbitrary blinding factors"
    );

    // To make it balance, we'd need: input_blinding == output1_blinding + output2_blinding (mod q)
    // This is the wallet's responsibility to construct correctly.
}

#[test]
fn test_transparent_and_confidential_mixed() {
    // Test transaction with both transparent and confidential outputs
    let transparent_value = 30u64;
    let transparent_output = Output::new(vec![0x07; 64], transparent_value, OutputMeta::default());

    let confidential_value = 70u64;
    let confidential_blinding = b"mixed_tx_blinding_32bytes!!!!!!!";
    let confidential_commitment = commit_value(confidential_value, confidential_blinding);
    let confidential_proof =
        prove_range(confidential_value, confidential_blinding).expect("proof should succeed");

    let confidential_output = Output::new_confidential(
        vec![0x08; 64],
        confidential_commitment.clone(),
        OutputMeta {
            deposit_flag: true,
            deposit_id: None,
        },
    );

    // Witness has 1 proof (only for confidential output)
    let witness = Witness::new(vec![confidential_proof.clone()], 77777u64, vec![]);

    let tx = TxBuilder::new()
        .add_output(transparent_output.clone())
        .add_output(confidential_output.clone())
        .set_witness(witness)
        .build();

    // Verify mixed outputs
    assert_eq!(tx.outputs.len(), 2, "should have 2 outputs");
    assert!(
        !tx.outputs[0].is_confidential(),
        "first should be transparent"
    );
    assert!(
        tx.outputs[1].is_confidential(),
        "second should be confidential"
    );

    assert_eq!(
        tx.outputs[0].value, transparent_value,
        "transparent value should be visible"
    );
    assert_eq!(tx.outputs[1].value, 0, "confidential value should be 0");

    // Witness should have exactly 1 proof
    assert_eq!(
        tx.witness.proof_count(),
        1,
        "witness should have 1 proof for 1 confidential output"
    );

    // Verify proof
    assert!(
        verify_range(&confidential_commitment, &tx.witness.range_proofs[0]),
        "proof should verify"
    );

    // Serialize and deserialize full transaction
    use codec::{from_slice_cbor, to_vec_cbor};
    let encoded = to_vec_cbor(&tx).expect("tx serialization should succeed");
    let decoded: Tx = from_slice_cbor(&encoded).expect("tx deserialization should succeed");

    assert_eq!(tx, decoded, "transaction should roundtrip correctly");
}

#[test]
fn test_witness_default() {
    // Test default witness creation
    let witness = Witness::default();

    assert_eq!(
        witness.proof_count(),
        0,
        "default witness should have 0 proofs"
    );
    assert_eq!(witness.stamp, 0, "default stamp should be 0");
    assert!(witness.extra.is_empty(), "default extra should be empty");
}

#[test]
fn test_output_meta_serialization() {
    // Test OutputMeta with deposit_id
    use codec::{from_slice_cbor, to_vec_cbor};

    let meta = OutputMeta {
        deposit_flag: true,
        deposit_id: Some([0x99; 32]),
    };

    let encoded = to_vec_cbor(&meta).expect("meta serialization should succeed");
    let decoded: OutputMeta =
        from_slice_cbor(&encoded).expect("meta deserialization should succeed");

    assert_eq!(meta, decoded, "meta should roundtrip correctly");
    assert!(decoded.deposit_flag, "deposit flag should be true");
    assert_eq!(
        decoded.deposit_id.unwrap(),
        [0x99; 32],
        "deposit_id should match"
    );
}
