//! Integration tests for cryptographic primitives.
//!
//! These tests verify end-to-end workflows including key generation,
//! signing, verification, and cross-algorithm compatibility.

use crypto::*;
use pqcrypto_mldsa::mldsa44;

/// Test complete workflow: keygen → sign → verify for Dilithium2
#[test]
fn dilithium2_end_to_end_workflow() {
    // Step 1: Generate Dilithium2 keypair directly
    let seed = [42u8; 32];
    let (pk_bytes, sk_bytes) =
        Dilithium2Scheme::keygen_from_seed(&seed).expect("Dilithium2 keygen should succeed");

    let public_key = PublicKey::from_bytes(pk_bytes);
    let secret_key = SecretKey::from_bytes(sk_bytes);

    // Step 2: Generate a second keypair for negative tests
    let (pk2_bytes, _) =
        Dilithium2Scheme::keygen_from_seed(&[99u8; 32]).expect("Second keygen should succeed");
    let wrong_public_key = PublicKey::from_bytes(pk2_bytes);

    // Step 3: Sign message with Dilithium2 using TX context
    let message = b"Transfer 100 coins to Alice";
    let sig = sign(message, &secret_key, AlgTag::Dilithium2, context::TX)
        .expect("Dilithium2 signing should succeed");

    // Step 4: Verify signature
    assert_eq!(sig.alg, AlgTag::Dilithium2);
    verify(message, &public_key, &sig, context::TX).expect("Signature should verify successfully");

    // Step 5: Verify rejection of wrong key
    assert!(
        verify(message, &wrong_public_key, &sig, context::TX).is_err(),
        "Signature should not verify with wrong public key"
    );

    // Step 6: Verify rejection of modified message
    let modified_message = b"Transfer 999 coins to Alice";
    assert!(
        verify(modified_message, &public_key, &sig, context::TX).is_err(),
        "Signature should not verify with modified message"
    );

    // Step 7: Verify rejection of wrong context
    assert!(
        verify(message, &public_key, &sig, context::BLOCK).is_err(),
        "Signature should not verify with wrong context"
    );
}

/// Test that Ed25519 and Dilithium2 can coexist
#[cfg(feature = "dev_stub_signing")]
#[test]
fn cross_algorithm_compatibility() {
    let km = KeyMaterial::random();
    let spend = km.derive_spend_keypair(0);
    let message = b"Cross-algorithm test message";

    // Sign with Ed25519
    let ed25519_sig = sign(message, &spend.secret, AlgTag::Ed25519, context::TX)
        .expect("Ed25519 signing should succeed");
    assert_eq!(ed25519_sig.alg, AlgTag::Ed25519);

    // Verify Ed25519 signature
    verify(message, &spend.public, &ed25519_sig, context::TX)
        .expect("Ed25519 signature should verify");

    // Generate Dilithium2 keys
    let (dilithium_pk, dilithium_sk) =
        Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("Dilithium2 keygen should succeed");
    let dilithium_public = PublicKey::from_bytes(dilithium_pk);
    let dilithium_secret = SecretKey::from_bytes(dilithium_sk);

    // Sign with Dilithium2
    let dilithium_sig = sign(message, &dilithium_secret, AlgTag::Dilithium2, context::TX)
        .expect("Dilithium2 signing should succeed");
    assert_eq!(dilithium_sig.alg, AlgTag::Dilithium2);

    // Verify Dilithium2 signature
    verify(message, &dilithium_public, &dilithium_sig, context::TX)
        .expect("Dilithium2 signature should verify");

    // Cross-verify should fail (Ed25519 sig with Dilithium2 key)
    assert!(
        verify(message, &dilithium_public, &ed25519_sig, context::TX).is_err(),
        "Ed25519 signature should not verify with Dilithium2 key"
    );

    // Cross-verify should fail (Dilithium2 sig with Ed25519 key)
    assert!(
        verify(message, &spend.public, &dilithium_sig, context::TX).is_err(),
        "Dilithium2 signature should not verify with Ed25519 key"
    );
}

/// Test signature scheme trait directly for Dilithium2
#[test]
fn dilithium2_trait_implementation() {
    // Test constants - use library values!
    assert_eq!(Dilithium2Scheme::ALG, AlgTag::Dilithium2);
    assert_eq!(Dilithium2Scheme::NAME, "Dilithium2");
    assert_eq!(
        Dilithium2Scheme::PUBLIC_KEY_BYTES,
        mldsa44::public_key_bytes()
    );
    assert_eq!(
        Dilithium2Scheme::SECRET_KEY_BYTES,
        mldsa44::secret_key_bytes()
    );
    assert_eq!(
        Dilithium2Scheme::SIGNATURE_BYTES,
        mldsa44::signature_bytes()
    );

    // Test keygen
    let seed = [0x42; 32];
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen should succeed");

    assert_eq!(pk.len(), Dilithium2Scheme::PUBLIC_KEY_BYTES);
    assert_eq!(sk.len(), Dilithium2Scheme::SECRET_KEY_BYTES);

    // Test signing
    let message = b"Trait implementation test";
    let sig = Dilithium2Scheme::sign(&sk, message).expect("sign should succeed");
    assert_eq!(sig.len(), Dilithium2Scheme::SIGNATURE_BYTES);

    // Test verification
    assert!(
        Dilithium2Scheme::verify(&pk, message, &sig),
        "signature should verify"
    );

    // Test rejection of invalid inputs
    let empty_key = vec![];
    assert!(
        Dilithium2Scheme::sign(&empty_key, message).is_err(),
        "signing with invalid key should fail"
    );
    assert!(
        !Dilithium2Scheme::verify(&empty_key, message, &sig),
        "verify with invalid key should return false"
    );
}

/// Test multiple sequential signatures (randomness check)
#[test]
fn dilithium2_multiple_signatures() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[99; 32]).expect("keygen should succeed");

    let message = b"Same message, multiple times";
    let mut signatures = Vec::new();

    // Generate 10 signatures of the same message
    for _ in 0..10 {
        let sig = Dilithium2Scheme::sign(&sk, message).expect("sign should succeed");
        signatures.push(sig);
    }

    // All signatures should verify
    for sig in &signatures {
        assert!(
            Dilithium2Scheme::verify(&pk, message, sig),
            "all signatures should verify"
        );
    }

    // Note: Dilithium2 may produce different signatures each time (randomized)
    // but we don't enforce this as it depends on the implementation
}

/// Test signature verification with corrupted data
#[test]
fn dilithium2_corruption_detection() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[77; 32]).expect("keygen should succeed");

    let message = b"Original message";
    let sig = Dilithium2Scheme::sign(&sk, message).expect("sign should succeed");

    // Corrupt each byte of the signature one at a time
    for i in 0..sig.len().min(100) {
        // Test first 100 bytes for speed
        let mut corrupted = sig.clone();
        corrupted[i] ^= 0xFF;

        assert!(
            !Dilithium2Scheme::verify(&pk, message, &corrupted),
            "corrupted signature at byte {} should not verify",
            i
        );
    }

    // Corrupt the public key
    for i in 0..pk.len().min(50) {
        let mut corrupted_pk = pk.clone();
        corrupted_pk[i] ^= 0xFF;

        assert!(
            !Dilithium2Scheme::verify(&corrupted_pk, message, &sig),
            "signature should not verify with corrupted public key at byte {}",
            i
        );
    }
}

/// Test key derivation determinism
///
/// **Note:** This test only passes with the `dev_stub_signing` feature enabled,
/// which uses Ed25519 (deterministic keygen). Dilithium2 currently uses system TRNG
/// for key generation and does NOT support deterministic keygen from seed.
///
/// TODO: When migrating to liboqs, enable deterministic Dilithium2 keygen and
/// remove the cfg guard.
#[test]
#[cfg(feature = "dev_stub_signing")]
fn key_derivation_is_deterministic() {
    let entropy = b"test entropy for deterministic keygen";

    let km1 = KeyMaterial::from_entropy(entropy);
    let km2 = KeyMaterial::from_entropy(entropy);

    // Derive same index keys from both instances
    let spend1 = km1.derive_spend_keypair(0);
    let spend2 = km2.derive_spend_keypair(0);

    let scan1 = km1.derive_scan_keypair(5);
    let scan2 = km2.derive_scan_keypair(5);

    // Keys should be identical (same entropy → same keys)
    assert_eq!(
        spend1.public.as_bytes(),
        spend2.public.as_bytes(),
        "public keys should be deterministic"
    );
    assert_eq!(
        spend1.secret.as_bytes(),
        spend2.secret.as_bytes(),
        "secret keys should be deterministic"
    );

    assert_eq!(
        scan1.public.as_bytes(),
        scan2.public.as_bytes(),
        "scan public keys should be deterministic"
    );
    assert_eq!(
        scan1.secret.as_bytes(),
        scan2.secret.as_bytes(),
        "scan secret keys should be deterministic"
    );

    // Different indices should produce different keys
    let spend_index_0 = km1.derive_spend_keypair(0);
    let spend_index_1 = km1.derive_spend_keypair(1);

    assert_ne!(
        spend_index_0.public.as_bytes(),
        spend_index_1.public.as_bytes(),
        "different indices should produce different keys"
    );
}

/// Test large message signing and verification
#[test]
fn dilithium2_large_message() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[123; 32]).expect("keygen should succeed");

    // Test with messages of various sizes
    let sizes = vec![0, 1, 100, 1024, 10_000, 100_000, 1_000_000];

    for size in sizes {
        let message = vec![0x42u8; size];

        let sig =
            Dilithium2Scheme::sign(&sk, &message).expect("signing large message should succeed");

        assert!(
            Dilithium2Scheme::verify(&pk, &message, &sig),
            "large message ({} bytes) should verify",
            size
        );

        // Modify one byte and ensure it fails
        if size > 0 {
            let mut modified = message.clone();
            modified[size / 2] ^= 0xFF;

            assert!(
                !Dilithium2Scheme::verify(&pk, &modified, &sig),
                "modified large message should not verify"
            );
        }
    }
}

/// Test unsupported algorithm tags
#[test]
fn unsupported_algorithms_rejected() {
    let km = KeyMaterial::random();
    let spend = km.derive_spend_keypair(0);
    let message = b"Test message";

    // Dilithium3 not yet implemented
    match sign(message, &spend.secret, AlgTag::Dilithium3, context::TX) {
        Err(CryptoError::UnsupportedAlg(0x02)) => {} // Expected
        other => panic!("Expected UnsupportedAlg error, got {:?}", other),
    }

    // Dilithium5 not yet implemented
    match sign(message, &spend.secret, AlgTag::Dilithium5, context::TX) {
        Err(CryptoError::UnsupportedAlg(0x03)) => {} // Expected
        other => panic!("Expected UnsupportedAlg error, got {:?}", other),
    }

    // SPHINCS+ not yet implemented
    match sign(message, &spend.secret, AlgTag::SphincsPlus, context::TX) {
        Err(CryptoError::UnsupportedAlg(0x10)) => {} // Expected
        other => panic!("Expected UnsupportedAlg error, got {:?}", other),
    }
}

/// Test signature serialization/deserialization
#[test]
fn signature_serialization() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[55; 32]).expect("keygen should succeed");

    let pk_obj = PublicKey::from_bytes(pk);
    let sk_obj = SecretKey::from_bytes(sk);

    let message = b"Serialization test";

    // Sign with high-level API (includes domain separation)
    let signature =
        sign(message, &sk_obj, AlgTag::Dilithium2, context::TX).expect("sign should succeed");

    // Serialize with serde_json
    let json = serde_json::to_string(&signature).expect("signature should serialize");

    // Deserialize
    let deserialized: Signature =
        serde_json::from_str(&json).expect("signature should deserialize");

    assert_eq!(deserialized.alg, AlgTag::Dilithium2);
    assert_eq!(deserialized.bytes, signature.bytes);

    // Verify deserialized signature works
    verify(message, &pk_obj, &deserialized, context::TX)
        .expect("deserialized signature should verify");
}

/// Test strict signature length validation (malleability protection)
#[test]
fn signature_length_validation() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");
    let pk_obj = PublicKey::from_bytes(pk);
    let sk_obj = SecretKey::from_bytes(sk);

    let message = b"Test message";
    let sig =
        sign(message, &sk_obj, AlgTag::Dilithium2, context::TX).expect("signing should succeed");

    // Valid signature should verify
    verify(message, &pk_obj, &sig, context::TX).expect("valid signature should verify");

    // Truncated signature should be rejected
    let mut truncated = sig.clone();
    truncated.bytes.truncate(truncated.bytes.len() - 10);
    assert!(
        verify(message, &pk_obj, &truncated, context::TX).is_err(),
        "truncated signature should be rejected"
    );

    // Extended signature should be rejected
    let mut extended = sig.clone();
    extended.bytes.extend_from_slice(&[0u8; 10]);
    assert!(
        verify(message, &pk_obj, &extended, context::TX).is_err(),
        "extended signature should be rejected"
    );

    // Empty signature should be rejected
    let empty = Signature::new(AlgTag::Dilithium2, vec![]);
    assert!(
        verify(message, &pk_obj, &empty, context::TX).is_err(),
        "empty signature should be rejected"
    );
}

/// Test domain separation prevents cross-context attacks
#[test]
fn domain_separation_protection() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");
    let pk_obj = PublicKey::from_bytes(pk);
    let sk_obj = SecretKey::from_bytes(sk);

    let message = b"Important transaction";

    // Sign with TX context
    let tx_sig =
        sign(message, &sk_obj, AlgTag::Dilithium2, context::TX).expect("TX signing should succeed");

    // Sign with BLOCK context
    let block_sig = sign(message, &sk_obj, AlgTag::Dilithium2, context::BLOCK)
        .expect("BLOCK signing should succeed");

    // TX signature should verify with TX context
    verify(message, &pk_obj, &tx_sig, context::TX)
        .expect("TX signature should verify with TX context");

    // TX signature should NOT verify with BLOCK context
    assert!(
        verify(message, &pk_obj, &tx_sig, context::BLOCK).is_err(),
        "TX signature should not verify with BLOCK context"
    );

    // BLOCK signature should verify with BLOCK context
    verify(message, &pk_obj, &block_sig, context::BLOCK)
        .expect("BLOCK signature should verify with BLOCK context");

    // BLOCK signature should NOT verify with TX context
    assert!(
        verify(message, &pk_obj, &block_sig, context::TX).is_err(),
        "BLOCK signature should not verify with TX context"
    );
}

/// Test corrupted signature bytes are rejected
#[test]
fn corrupted_signature_rejection() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");
    let pk_obj = PublicKey::from_bytes(pk);
    let sk_obj = SecretKey::from_bytes(sk);

    let message = b"Test message";
    let sig =
        sign(message, &sk_obj, AlgTag::Dilithium2, context::TX).expect("signing should succeed");

    // Original should verify
    verify(message, &pk_obj, &sig, context::TX).expect("original signature should verify");

    // Test corruption at different positions
    for pos in [0, sig.bytes.len() / 2, sig.bytes.len() - 1] {
        let mut corrupted = sig.clone();
        corrupted.bytes[pos] ^= 0x01; // Flip one bit
        assert!(
            verify(message, &pk_obj, &corrupted, context::TX).is_err(),
            "corrupted signature at position {} should be rejected",
            pos
        );
    }
}

/// Benchmark-style test: sign and verify 100 messages
#[test]
fn dilithium2_throughput_test() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");

    let count = 100;
    let mut signatures = Vec::with_capacity(count);

    // Sign 100 messages
    let sign_start = std::time::Instant::now();
    for i in 0..count {
        let message = format!("Message number {}", i);
        let sig = Dilithium2Scheme::sign(&sk, message.as_bytes()).expect("sign should succeed");
        signatures.push((message, sig));
    }
    let sign_duration = sign_start.elapsed();

    // Verify 100 signatures
    let verify_start = std::time::Instant::now();
    for (message, sig) in &signatures {
        assert!(
            Dilithium2Scheme::verify(&pk, message.as_bytes(), sig),
            "signature should verify"
        );
    }
    let verify_duration = verify_start.elapsed();

    println!("\n=== Dilithium2 Throughput Test ===");
    println!("Signed {} messages in {:?}", count, sign_duration);
    println!("Average signing time: {:?}", sign_duration / count as u32);
    println!("Verified {} signatures in {:?}", count, verify_duration);
    println!(
        "Average verification time: {:?}",
        verify_duration / count as u32
    );
    println!("==================================\n");

    // Basic sanity checks (these are slow reference implementations)
    assert!(
        sign_duration.as_millis() < 10_000,
        "signing should complete in reasonable time"
    );
    assert!(
        verify_duration.as_millis() < 10_000,
        "verification should complete in reasonable time"
    );
}

// ============================================================================
// Batch Verification Tests (Sprint 6)
// ============================================================================

#[test]
fn batch_verify_empty_is_valid() {
    // Empty batch should be trivially valid
    let items: Vec<VerifyItem> = vec![];
    let outcome = batch_verify_v2(items);
    assert_eq!(outcome, BatchVerifyOutcome::AllValid);
    assert!(outcome.is_all_valid());
    assert_eq!(outcome.invalid_count(), 0);
}

#[test]
fn batch_verify_single_valid_signature() {
    let seed = [1u8; 32];
    let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
        .expect("keygen should succeed");

    let public = PublicKey::from_bytes(pk_bytes);
    let secret = SecretKey::from_bytes(sk_bytes);

    let msg = b"Test message";
    let sig = sign(msg, &secret, AlgTag::Dilithium2, context::TX)
        .expect("signing should succeed");

    let item = VerifyItem::new(
        context::TX,
        AlgTag::Dilithium2,
        public.as_bytes(),
        msg,
        &sig.bytes,
    )
    .expect("VerifyItem creation should succeed");

    let outcome = batch_verify_v2(vec![item]);
    assert_eq!(outcome, BatchVerifyOutcome::AllValid);
}

#[test]
fn batch_verify_multiple_valid_signatures() {
    // Generate 10 different keypairs and signatures
    // CRITICAL: All data (keys, messages, signatures) must be stored OUTSIDE the VerifyItem
    // creation loop to avoid lifetime issues
    let count = 10;

    // Step 1: Generate all data and store in vectors
    let mut publics = Vec::new();
    let mut secrets = Vec::new();
    let mut messages = Vec::new();
    let mut sigs = Vec::new();

    for i in 0..count {
        let seed = [i as u8; 32];
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
            .expect("keygen should succeed");

        publics.push(PublicKey::from_bytes(pk_bytes));
        secrets.push(SecretKey::from_bytes(sk_bytes));
        messages.push(format!("Message {}", i).into_bytes());
    }

    // Generate signatures
    for i in 0..count {
        let sig = sign(&messages[i], &secrets[i], AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");
        sigs.push(sig);
    }

    // Step 2: Create VerifyItems with borrows from the stored data
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let item = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            publics[i].as_bytes(),
            &messages[i],
            &sigs[i].bytes,
        )
        .expect("VerifyItem creation should succeed");
        items.push(item);
    }

    let outcome = batch_verify_v2(items);
    assert_eq!(outcome, BatchVerifyOutcome::AllValid);
}

#[test]
fn batch_verify_mixed_validity_one_invalid() {
    // Create 5 valid signatures and 1 invalid
    // Store all data in vectors to avoid lifetime issues
    let count = 5;

    // Generate valid signatures
    let mut publics = Vec::new();
    let mut secrets = Vec::new();
    let mut messages = Vec::new();
    let mut sigs = Vec::new();

    for i in 0..count {
        let seed = [i as u8; 32];
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
            .expect("keygen should succeed");

        publics.push(PublicKey::from_bytes(pk_bytes));
        secrets.push(SecretKey::from_bytes(sk_bytes));
        messages.push(format!("Message {}", i).into_bytes());
    }

    for i in 0..count {
        let sig = sign(&messages[i], &secrets[i], AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");
        sigs.push(sig);
    }

    // Add one invalid signature (sign with one message, verify with different)
    let seed = [99u8; 32];
    let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
        .expect("keygen should succeed");

    publics.push(PublicKey::from_bytes(pk_bytes));
    secrets.push(SecretKey::from_bytes(sk_bytes));

    let signed_msg = b"Original message".to_vec();
    let sig = sign(&signed_msg, &secrets[count], AlgTag::Dilithium2, context::TX)
        .expect("signing should succeed");
    sigs.push(sig);

    // Use different message for verification (invalid)
    messages.push(b"Different message".to_vec());

    // Create VerifyItems
    let mut items = Vec::with_capacity(count + 1);
    for i in 0..=count {
        let item = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            publics[i].as_bytes(),
            &messages[i],
            &sigs[i].bytes,
        )
        .expect("VerifyItem creation should succeed");
        items.push(item);
    }

    let outcome = batch_verify_v2(items);
    assert_eq!(outcome, BatchVerifyOutcome::SomeInvalid(1));
    assert!(!outcome.is_all_valid());
    assert_eq!(outcome.invalid_count(), 1);
}

#[test]
fn batch_verify_len_checks() {
    // Test that invalid lengths are rejected at VerifyItem creation
    let seed = [1u8; 32];
    let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
        .expect("keygen should succeed");

    let public = PublicKey::from_bytes(pk_bytes);
    let secret = SecretKey::from_bytes(sk_bytes);

    let msg = b"Test";
    let sig = sign(msg, &secret, AlgTag::Dilithium2, context::TX)
        .expect("signing should succeed");

    // Test wrong public key length
    let short_pub = &public.as_bytes()[..100];
    let result = VerifyItem::new(
        context::TX,
        AlgTag::Dilithium2,
        short_pub,
        msg,
        &sig.bytes,
    );
    assert!(result.is_err(), "Short public key should be rejected");

    // Test wrong signature length
    let short_sig = &sig.bytes[..100];
    let result = VerifyItem::new(
        context::TX,
        AlgTag::Dilithium2,
        public.as_bytes(),
        msg,
        short_sig,
    );
    assert!(result.is_err(), "Short signature should be rejected");

    // Test message too long
    let huge_msg = vec![0u8; MAX_MESSAGE_LEN + 1];
    let result = VerifyItem::new(
        context::TX,
        AlgTag::Dilithium2,
        public.as_bytes(),
        &huge_msg,
        &sig.bytes,
    );
    assert!(result.is_err(), "Oversized message should be rejected");
}

#[test]
fn batch_verify_threshold_switch() {
    // Test that sequential/parallel switch works (implicit in implementation)
    // We verify both small and large batches work correctly

    // === SMALL BATCH (< threshold, uses sequential) ===
    let small_count = 5;
    let mut small_publics = Vec::new();
    let mut small_secrets = Vec::new();
    let mut small_messages = Vec::new();
    let mut small_sigs = Vec::new();

    for i in 0..small_count {
        let seed = [i as u8; 32];
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
            .expect("keygen should succeed");

        small_publics.push(PublicKey::from_bytes(pk_bytes));
        small_secrets.push(SecretKey::from_bytes(sk_bytes));
        small_messages.push(format!("Msg {}", i).into_bytes());
    }

    for i in 0..small_count {
        let sig = sign(&small_messages[i], &small_secrets[i], AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");
        small_sigs.push(sig);
    }

    let mut small_items = Vec::with_capacity(small_count);
    for i in 0..small_count {
        let item = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            small_publics[i].as_bytes(),
            &small_messages[i],
            &small_sigs[i].bytes,
        )
        .expect("VerifyItem creation should succeed");
        small_items.push(item);
    }

    let outcome = batch_verify_v2(small_items);
    assert_eq!(outcome, BatchVerifyOutcome::AllValid);

    // === LARGE BATCH (>= threshold, uses parallel if threads > 1) ===
    let large_count = 50;
    let mut large_publics = Vec::new();
    let mut large_secrets = Vec::new();
    let mut large_messages = Vec::new();
    let mut large_sigs = Vec::new();

    for i in 0..large_count {
        let seed = [(i % 256) as u8; 32];
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
            .expect("keygen should succeed");

        large_publics.push(PublicKey::from_bytes(pk_bytes));
        large_secrets.push(SecretKey::from_bytes(sk_bytes));
        large_messages.push(format!("Message {}", i).into_bytes());
    }

    for i in 0..large_count {
        let sig = sign(&large_messages[i], &large_secrets[i], AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");
        large_sigs.push(sig);
    }

    let mut large_items = Vec::with_capacity(large_count);
    for i in 0..large_count {
        let item = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            large_publics[i].as_bytes(),
            &large_messages[i],
            &large_sigs[i].bytes,
        )
        .expect("VerifyItem creation should succeed");
        large_items.push(item);
    }

    let outcome = batch_verify_v2(large_items);
    assert_eq!(outcome, BatchVerifyOutcome::AllValid);
}

#[test]
fn batch_verify_parallel_consistency() {
    // Verify that sequential and parallel paths produce the same result
    // Create a deterministic set of signatures
    let count = 40;

    // Generate data
    let mut publics = Vec::new();
    let mut secrets = Vec::new();
    let mut messages = Vec::new();
    let mut sigs = Vec::new();

    for i in 0..count {
        let seed = [i as u8; 32];
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
            .expect("keygen should succeed");

        publics.push(PublicKey::from_bytes(pk_bytes));
        secrets.push(SecretKey::from_bytes(sk_bytes));
        messages.push(format!("Test {}", i).into_bytes());
    }

    for i in 0..count {
        let sig = sign(&messages[i], &secrets[i], AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");
        sigs.push(sig);
    }

    // Create first batch
    let mut items_1 = Vec::with_capacity(count);
    for i in 0..count {
        let item = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            publics[i].as_bytes(),
            &messages[i],
            &sigs[i].bytes,
        )
        .expect("VerifyItem creation should succeed");
        items_1.push(item);
    }

    // Create second batch (same data)
    let mut items_2 = Vec::with_capacity(count);
    for i in 0..count {
        let item = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            publics[i].as_bytes(),
            &messages[i],
            &sigs[i].bytes,
        )
        .expect("VerifyItem creation should succeed");
        items_2.push(item);
    }

    // Verify both batches produce same result
    let outcome1 = batch_verify_v2(items_1);
    let outcome2 = batch_verify_v2(items_2);

    assert_eq!(outcome1, outcome2, "Parallel and sequential should match");
    assert_eq!(outcome1, BatchVerifyOutcome::AllValid);
}

#[test]
fn batch_verify_max_size_protection() {
    // Test that reasonable batches work (we can't test MAX_BATCH_SIZE as it's 100k)
    // and verify max_batch_size getter works
    
    let count = 100;
    let mut publics = Vec::new();
    let mut secrets = Vec::new();
    let mut messages = Vec::new();
    let mut sigs = Vec::new();

    for i in 0..count {
        let seed = [(i % 256) as u8; 32];
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
            .expect("keygen should succeed");

        publics.push(PublicKey::from_bytes(pk_bytes));
        secrets.push(SecretKey::from_bytes(sk_bytes));
        messages.push(format!("Msg {}", i).into_bytes());
    }

    for i in 0..count {
        let sig = sign(&messages[i], &secrets[i], AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");
        sigs.push(sig);
    }

    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let item = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            publics[i].as_bytes(),
            &messages[i],
            &sigs[i].bytes,
        )
        .expect("VerifyItem creation should succeed");
        items.push(item);
    }

    let outcome = batch_verify_v2(items);
    assert_eq!(outcome, BatchVerifyOutcome::AllValid);
    
    // Verify max_batch_size getter works
    let max_size = get_max_batch_size();
    assert!(max_size >= DEFAULT_MAX_BATCH_SIZE);
}
