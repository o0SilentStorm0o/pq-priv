//! Integration tests for transaction signing with Dilithium2.
//!
//! These tests verify that transactions can be properly signed and
//! verified using post-quantum signatures.

use crypto::{
    AlgTag, Dilithium2Scheme, PublicKey, SecretKey, SignatureScheme, compute_link_tag, context,
    random_nonce,
};
use tx::{Input, Output, OutputMeta, Tx, TxBuilder, binding_hash, input_auth_message};

/// Helper to build a signed input with explicit algorithm choice
fn build_dilithium2_input(
    prev_txid: [u8; 32],
    prev_index: u32,
    public: &PublicKey,
    secret: &SecretKey,
    ring_proof: Vec<u8>,
    binding_hash: &[u8; 32],
) -> Input {
    let nonce = random_nonce::<16>();
    let link = compute_link_tag(public, &nonce);

    // Compute auth message
    let mut hasher = blake3::Hasher::new();
    hasher.update(&prev_txid);
    hasher.update(&prev_index.to_le_bytes());
    hasher.update(&link);
    hasher.update(public.as_bytes());
    hasher.update(binding_hash);
    hasher.update(blake3::hash(&ring_proof).as_bytes());
    let message: [u8; 32] = hasher.finalize().into();

    // Sign with Dilithium2 explicitly using TX context
    let signature = crypto::sign(&message, secret, AlgTag::Dilithium2, context::TX)
        .expect("Dilithium2 signing should succeed");

    Input::new(
        prev_txid,
        prev_index,
        link,
        public.clone(),
        ring_proof,
        signature,
    )
}

/// Test signing a transaction input with Dilithium2
#[test]
fn sign_transaction_input_with_dilithium2() {
    // Generate Dilithium2 keypair
    let (pk_bytes, sk_bytes) =
        Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");

    let public_key = PublicKey::from_bytes(pk_bytes);
    let secret_key = SecretKey::from_bytes(sk_bytes);

    // Create a transaction output
    let output = Output::new(vec![1, 2, 3, 4], 100, OutputMeta::default());

    // Calculate binding hash
    let witness = tx::Witness::default();
    let binding = binding_hash(std::slice::from_ref(&output), &witness);

    // Build signed input with Dilithium2
    let prev_txid = [7u8; 32];
    let prev_index = 0;
    let ring_proof = vec![0x42, 0x43, 0x44];

    let input = build_dilithium2_input(
        prev_txid,
        prev_index,
        &public_key,
        &secret_key,
        ring_proof.clone(),
        &binding,
    );

    // Verify the signature in the input
    let auth_msg = input_auth_message(&input, &binding);

    // Check algorithm tag
    assert_eq!(input.pq_signature.alg, AlgTag::Dilithium2);

    // Verify signature with TX context
    crypto::verify(
        &auth_msg,
        &input.spend_public,
        &input.pq_signature,
        context::TX,
    )
    .expect("transaction signature should verify");
}

/// Test complete transaction workflow
#[test]
fn complete_transaction_workflow() {
    // Generate two keypairs (sender and receiver)
    let (sender_pk, sender_sk) =
        Dilithium2Scheme::keygen_from_seed(&[1; 32]).expect("sender keygen");
    let (receiver_pk, _) = Dilithium2Scheme::keygen_from_seed(&[2; 32]).expect("receiver keygen");

    let sender_public = PublicKey::from_bytes(sender_pk);
    let sender_secret = SecretKey::from_bytes(sender_sk);

    // Create transaction outputs
    let output1 = Output::new(receiver_pk.clone(), 5000, OutputMeta::default());

    let output2 = Output::new(
        vec![0xFF; 64], // Change output
        3000,
        OutputMeta::default(),
    );

    // Build witness and calculate binding hash
    let witness = tx::Witness::default();
    let binding = binding_hash(&[output1.clone(), output2.clone()], &witness);

    // Create two inputs (spending previous UTXOs)
    let input1 = build_dilithium2_input(
        [10u8; 32],
        0,
        &sender_public,
        &sender_secret,
        vec![0xAA],
        &binding,
    );

    let input2 = build_dilithium2_input(
        [20u8; 32],
        1,
        &sender_public,
        &sender_secret,
        vec![0xBB],
        &binding,
    );

    // Build complete transaction
    let tx = TxBuilder::new()
        .add_input(input1.clone())
        .add_input(input2.clone())
        .add_output(output1)
        .add_output(output2)
        .set_witness(witness.clone())
        .build();

    // Verify all input signatures
    let binding_check = binding_hash(&tx.outputs, &tx.witness);
    assert_eq!(binding, binding_check, "binding hash should match");

    for input in &tx.inputs {
        let auth_msg = input_auth_message(input, &binding_check);
        crypto::verify(
            &auth_msg,
            &input.spend_public,
            &input.pq_signature,
            context::TX,
        )
        .expect("input signature should verify");
    }

    // Verify transaction has an ID
    let txid = tx.txid();
    assert_eq!(txid.as_bytes().len(), 32);
}

/// Test transaction with multiple algorithms (if dev_stub_signing enabled)
#[cfg(feature = "dev_stub_signing")]
#[test]
fn transaction_with_mixed_algorithms() {
    use crypto::{Ed25519Stub, sign};

    // Create Ed25519 keypair
    let (ed_pk, ed_sk) = Ed25519Stub::keygen_from_seed(&[33; 32]).expect("ed25519 keygen");
    let ed_spend = crypto::SpendKeypair {
        public: PublicKey::from_bytes(ed_pk),
        secret: SecretKey::from_bytes(ed_sk),
    };

    // Create Dilithium2 keypair
    let (dil_pk, dil_sk) =
        Dilithium2Scheme::keygen_from_seed(&[44; 32]).expect("dilithium2 keygen");
    let dil_spend = crypto::SpendKeypair {
        public: PublicKey::from_bytes(dil_pk),
        secret: SecretKey::from_bytes(dil_sk),
    };

    // Create output
    let output = Output::new(vec![1, 2, 3], 1000, OutputMeta::default());
    let witness = tx::Witness::default();
    let _binding = binding_hash(std::slice::from_ref(&output), &witness);

    // Create input signed with Ed25519 (manual signing to override default)
    let message = b"ed25519 test";
    let ed_sig =
        sign(message, &ed_spend.secret, AlgTag::Ed25519, context::TX).expect("ed25519 sign");

    assert_eq!(ed_sig.alg, AlgTag::Ed25519);
    crypto::verify(message, &ed_spend.public, &ed_sig, context::TX)
        .expect("ed25519 sig should verify");

    // Create input signed with Dilithium2
    let dil_sig =
        sign(message, &dil_spend.secret, AlgTag::Dilithium2, context::TX).expect("dilithium2 sign");

    assert_eq!(dil_sig.alg, AlgTag::Dilithium2);
    crypto::verify(message, &dil_spend.public, &dil_sig, context::TX)
        .expect("dilithium2 sig should verify");

    // Cross-verification should fail
    assert!(crypto::verify(message, &dil_spend.public, &ed_sig, context::TX).is_err());
    assert!(crypto::verify(message, &ed_spend.public, &dil_sig, context::TX).is_err());
}

/// Test transaction serialization and deserialization
#[test]
fn transaction_serialization() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[55; 32]).expect("keygen");

    let public = PublicKey::from_bytes(pk);
    let secret = SecretKey::from_bytes(sk);

    // Build transaction
    let output = Output::new(vec![0xAB, 0xCD], 2500, OutputMeta::default());
    let witness = tx::Witness::default();
    let binding = binding_hash(std::slice::from_ref(&output), &witness);

    let input = build_dilithium2_input([9u8; 32], 0, &public, &secret, vec![0x11], &binding);

    let tx = TxBuilder::new()
        .add_input(input)
        .add_output(output)
        .set_witness(witness)
        .build();

    // Serialize to CBOR
    let serialized = codec::to_vec_cbor(&tx).expect("tx should serialize");

    // Deserialize
    let deserialized: Tx = codec::from_slice_cbor(&serialized).expect("tx should deserialize");

    // Verify txid matches
    assert_eq!(tx.txid(), deserialized.txid());

    // Verify signatures still work
    let binding_check = binding_hash(&deserialized.outputs, &deserialized.witness);
    for input in &deserialized.inputs {
        let auth_msg = input_auth_message(input, &binding_check);
        crypto::verify(
            &auth_msg,
            &input.spend_public,
            &input.pq_signature,
            context::TX,
        )
        .expect("deserialized signature should verify");
    }
}

/// Stress test: create and verify 50 transactions
#[test]
fn stress_test_multiple_transactions() {
    let count = 50;
    let mut transactions = Vec::new();

    println!("\nGenerating {} transactions...", count);

    for i in 0..count {
        let seed = [i as u8; 32];
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen");

        let public = PublicKey::from_bytes(pk);
        let secret = SecretKey::from_bytes(sk);

        let output = Output::new(vec![i as u8; 16], (i as u64) * 1000, OutputMeta::default());

        let witness = tx::Witness::default();
        let binding = binding_hash(std::slice::from_ref(&output), &witness);

        let input =
            build_dilithium2_input([i as u8; 32], i, &public, &secret, vec![0x77], &binding);

        let tx = TxBuilder::new()
            .add_input(input)
            .add_output(output)
            .set_witness(witness)
            .build();

        transactions.push(tx);
    }

    println!("Verifying {} transactions...", count);

    // Verify all transactions
    let start = std::time::Instant::now();
    for tx in &transactions {
        let binding = binding_hash(&tx.outputs, &tx.witness);
        for input in &tx.inputs {
            let auth_msg = input_auth_message(input, &binding);
            crypto::verify(
                &auth_msg,
                &input.spend_public,
                &input.pq_signature,
                context::TX,
            )
            .expect("signature should verify");
        }
    }
    let duration = start.elapsed();

    println!("Verified {} transactions in {:?}", count, duration);
    println!("Average per transaction: {:?}\n", duration / count);
}
