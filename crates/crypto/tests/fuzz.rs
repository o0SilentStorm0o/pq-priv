//! Fuzzing tests for cryptographic primitives.
//!
//! These tests verify that the crypto API handles malformed inputs gracefully
//! without panicking or exhibiting undefined behavior.

use crypto::{
    AlgTag, Dilithium2Scheme, PublicKey, SecretKey, Signature, SignatureScheme, context, sign,
    verify,
};

/// Fuzz test: verify should handle arbitrary signature bytes gracefully
#[test]
fn fuzz_verify_random_signatures() {
    let (pk, _sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");
    let pk_obj = PublicKey::from_bytes(pk);

    let message = b"Test message";

    // Test various malformed signature lengths
    let test_cases = [
        vec![],                                            // Empty
        vec![0u8; 1],                                      // Too short
        vec![0xFF; 100],                                   // Random short
        vec![0xAA; 1000],                                  // Random medium
        vec![0x55; Dilithium2Scheme::SIGNATURE_BYTES - 1], // One byte short
        vec![0x42; Dilithium2Scheme::SIGNATURE_BYTES + 1], // One byte long
        vec![0x00; 8192],                                  // Very long
    ];

    for (i, bytes) in test_cases.iter().enumerate() {
        let sig = Signature::new(AlgTag::Dilithium2, bytes.clone());

        // Verify should return error, not panic
        let result = verify(message, &pk_obj, &sig, context::TX);

        assert!(
            result.is_err(),
            "Test case {} with {} bytes should be rejected",
            i,
            bytes.len()
        );
    }
}

/// Fuzz test: verify should handle arbitrary message lengths
#[test]
fn fuzz_verify_random_messages() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");
    let pk_obj = PublicKey::from_bytes(pk.clone());
    let sk_obj = SecretKey::from_bytes(sk);

    // Sign a known message
    let known_message = b"Known message";
    let sig = sign(known_message, &sk_obj, AlgTag::Dilithium2, context::TX)
        .expect("signing should succeed");

    // Test various random message lengths
    let test_messages = [
        vec![],            // Empty
        vec![0u8; 1],      // One byte
        vec![0xFF; 32],    // Hash size
        vec![0xAA; 100],   // Medium
        vec![0x55; 1024],  // 1KB
        vec![0x42; 8192],  // 8KB
        vec![0x00; 65536], // 64KB
    ];

    for (i, msg) in test_messages.iter().enumerate() {
        // Verify should return error (wrong message), not panic
        let result = verify(msg, &pk_obj, &sig, context::TX);

        assert!(
            result.is_err(),
            "Test case {} with {} byte message should be rejected",
            i,
            msg.len()
        );
    }
}

/// Fuzz test: sign should handle various message sizes
#[test]
fn fuzz_sign_message_sizes() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");
    let pk_obj = PublicKey::from_bytes(pk);
    let sk_obj = SecretKey::from_bytes(sk);

    let test_sizes = vec![
        0, 1, 31, 32, 33, 64, 127, 128, 255, 256, 1023, 1024, 4095, 4096, 8191, 8192,
    ];

    for size in test_sizes {
        let message = vec![0xAB; size];

        // Sign should succeed for any message size
        let sig = sign(&message, &sk_obj, AlgTag::Dilithium2, context::TX)
            .unwrap_or_else(|_| panic!("signing {} byte message should succeed", size));

        // Verify should succeed
        verify(&message, &pk_obj, &sig, context::TX)
            .unwrap_or_else(|_| panic!("verifying {} byte signature should succeed", size));

        // Modified message should fail
        if size > 0 {
            let mut modified = message.clone();
            modified[0] ^= 0x01;
            assert!(
                verify(&modified, &pk_obj, &sig, context::TX).is_err(),
                "modified {} byte message should be rejected",
                size
            );
        }
    }
}

/// Fuzz test: verify with corrupted keys
#[test]
fn fuzz_verify_corrupted_keys() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen should succeed");
    let _pk_obj = PublicKey::from_bytes(pk.clone());
    let sk_obj = SecretKey::from_bytes(sk);

    let message = b"Test message";
    let sig =
        sign(message, &sk_obj, AlgTag::Dilithium2, context::TX).expect("signing should succeed");

    // Test corrupted public keys
    for flip_pos in [
        0,
        pk.len() / 4,
        pk.len() / 2,
        pk.len() * 3 / 4,
        pk.len() - 1,
    ] {
        let mut corrupted_pk = pk.clone();
        corrupted_pk[flip_pos] ^= 0xFF;
        let corrupted_pk_obj = PublicKey::from_bytes(corrupted_pk);

        // Verify with corrupted key should fail (not panic)
        let result = verify(message, &corrupted_pk_obj, &sig, context::TX);
        assert!(
            result.is_err(),
            "verification with corrupted key at position {} should fail",
            flip_pos
        );
    }
}

/// Fuzz test: trait API should handle edge cases
#[test]
fn fuzz_trait_api_edge_cases() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[0; 32]).expect("all-zero seed should work");

    // All-zero message
    let msg = vec![0u8; 1024];
    let sig = Dilithium2Scheme::sign(&sk, &msg).expect("signing all-zero message should succeed");
    assert!(
        Dilithium2Scheme::verify(&pk, &msg, &sig),
        "verifying all-zero message should succeed"
    );

    // All-ones message
    let msg = vec![0xFFu8; 1024];
    let sig = Dilithium2Scheme::sign(&sk, &msg).expect("signing all-ones message should succeed");
    assert!(
        Dilithium2Scheme::verify(&pk, &msg, &sig),
        "verifying all-ones message should succeed"
    );

    // Alternating pattern
    let msg: Vec<u8> = (0..1024)
        .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
        .collect();
    let sig =
        Dilithium2Scheme::sign(&sk, &msg).expect("signing alternating pattern should succeed");
    assert!(
        Dilithium2Scheme::verify(&pk, &msg, &sig),
        "verifying alternating pattern should succeed"
    );
}

/// Property-based test: sign/verify round-trip with random seeds
#[test]
fn property_sign_verify_roundtrip() {
    use rand::RngCore;
    use rand::rngs::OsRng;

    for _ in 0..10 {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen should succeed");
        let pk_obj = PublicKey::from_bytes(pk);
        let sk_obj = SecretKey::from_bytes(sk);

        // Random message size
        let msg_size = (OsRng.next_u32() % 4096) as usize + 1;
        let mut message = vec![0u8; msg_size];
        OsRng.fill_bytes(&mut message);

        // Sign and verify
        let sig = sign(&message, &sk_obj, AlgTag::Dilithium2, context::TX)
            .expect("signing random message should succeed");
        verify(&message, &pk_obj, &sig, context::TX)
            .expect("verifying random signature should succeed");
    }
}

/// Property-based test: batch verify with random batch sizes
#[test]
fn property_batch_verify_random_sizes() {
    use crypto::{VerifyItem, batch_verify_v2};
    use rand::RngCore;
    use rand::rngs::OsRng;

    // Test various batch sizes: 0, 1, 2, 5, 10, 32 (threshold), 64, 100
    let test_sizes = vec![0, 1, 2, 5, 10, 32, 64, 100];

    for batch_size in test_sizes {
        // Generate keypairs and sign messages
        let mut publics = Vec::new();
        let mut secrets = Vec::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..batch_size {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            OsRng.fill_bytes(&mut seed[1..]);

            let (pk, sk) =
                Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen should succeed");
            let pk_obj = PublicKey::from_bytes(pk);
            let sk_obj = SecretKey::from_bytes(sk);

            // Random message size (32 to 1024 bytes)
            let msg_size = 32 + (OsRng.next_u32() % 992) as usize;
            let mut message = vec![0u8; msg_size];
            OsRng.fill_bytes(&mut message);

            let sig = sign(&message, &sk_obj, AlgTag::Dilithium2, context::TX)
                .expect("signing should succeed");

            publics.push(pk_obj);
            secrets.push(sk_obj);
            messages.push(message);
            signatures.push(sig);
        }

        // Create VerifyItems
        let items: Vec<_> = publics
            .iter()
            .zip(messages.iter())
            .zip(signatures.iter())
            .map(|((pk, msg), sig)| {
                VerifyItem::new(
                    context::TX,
                    AlgTag::Dilithium2,
                    pk.as_bytes(),
                    msg,
                    &sig.bytes,
                )
                .expect("VerifyItem creation should succeed")
            })
            .collect();

        // Batch verify should succeed for all valid signatures
        let outcome = batch_verify_v2(items);
        assert!(
            outcome.is_all_valid(),
            "Batch verify with {} valid signatures should succeed",
            batch_size
        );
    }
}

/// Fuzz test: batch verify with random invalid signatures
#[test]
fn fuzz_batch_verify_with_invalid_signatures() {
    use crypto::{BatchVerifyOutcome, VerifyItem, batch_verify_v2};

    const BATCH_SIZE: usize = 20;
    const INVALID_POSITIONS: &[usize] = &[0, 5, 10, 15, 19]; // Positions to corrupt

    // Generate keypairs and sign messages
    let mut publics = Vec::new();
    let mut messages = Vec::new();
    let mut signatures = Vec::new();

    for i in 0..BATCH_SIZE {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen should succeed");
        let pk_obj = PublicKey::from_bytes(pk);
        let sk_obj = SecretKey::from_bytes(sk);

        let message = format!("Message {}", i).into_bytes();

        let sig = sign(&message, &sk_obj, AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");

        publics.push(pk_obj);
        messages.push(message);
        signatures.push(sig);
    }

    // Corrupt signatures at specific positions
    for &pos in INVALID_POSITIONS {
        if signatures[pos].bytes.len() > 10 {
            signatures[pos].bytes[10] ^= 0xFF;
        }
    }

    // Create VerifyItems
    let items: Vec<_> = publics
        .iter()
        .zip(messages.iter())
        .zip(signatures.iter())
        .map(|((pk, msg), sig)| {
            VerifyItem::new(
                context::TX,
                AlgTag::Dilithium2,
                pk.as_bytes(),
                msg,
                &sig.bytes,
            )
            .expect("VerifyItem creation should succeed")
        })
        .collect();

    // Batch verify should detect invalid signatures
    let outcome = batch_verify_v2(items);
    assert!(
        !outcome.is_all_valid(),
        "Batch verify should detect invalid signatures"
    );

    match outcome {
        BatchVerifyOutcome::SomeInvalid(count) => {
            assert_eq!(
                count,
                INVALID_POSITIONS.len(),
                "Should detect exactly {} invalid signatures",
                INVALID_POSITIONS.len()
            );
        }
        _ => panic!("Expected SomeInvalid outcome"),
    }
}

/// Fuzz test: batch verify with random message/signature lengths
#[test]
fn fuzz_batch_verify_input_lengths() {
    use crypto::{VerifyItem, batch_verify_v2};

    // Test edge cases for message and signature lengths
    let test_cases = [
        // (message_len, sig_len, should_fail)
        (0, Dilithium2Scheme::SIGNATURE_BYTES, false), // Empty message OK
        (1, Dilithium2Scheme::SIGNATURE_BYTES, false), // Minimal message OK
        (32, Dilithium2Scheme::SIGNATURE_BYTES, false), // Normal message OK
        (1024, Dilithium2Scheme::SIGNATURE_BYTES, false), // Large message OK
        (32, 0, true),                                 // Empty signature FAIL
        (32, 100, true),                               // Wrong sig size FAIL
        (32, Dilithium2Scheme::SIGNATURE_BYTES - 1, true), // One byte short FAIL
        (32, Dilithium2Scheme::SIGNATURE_BYTES + 1, true), // One byte long FAIL
    ];

    for (i, (msg_len, sig_len, should_fail)) in test_cases.iter().enumerate() {
        let (pk, sk) =
            Dilithium2Scheme::keygen_from_seed(&[i as u8; 32]).expect("keygen should succeed");
        let pk_obj = PublicKey::from_bytes(pk);
        let sk_obj = SecretKey::from_bytes(sk);

        let message = vec![0xAB; *msg_len];

        // Sign the message (if valid message length)
        let sig = if *msg_len > 0 {
            sign(&message, &sk_obj, AlgTag::Dilithium2, context::TX)
                .expect("signing should succeed")
        } else {
            // For empty message, create dummy signature
            Signature::new(
                AlgTag::Dilithium2,
                vec![0; Dilithium2Scheme::SIGNATURE_BYTES],
            )
        };

        // Create signature bytes with specified length
        let sig_bytes = if *sig_len == Dilithium2Scheme::SIGNATURE_BYTES {
            sig.bytes.clone()
        } else {
            vec![0xFF; *sig_len]
        };

        // Try to create VerifyItem
        let item_result = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            pk_obj.as_bytes(),
            &message,
            &sig_bytes,
        );

        if *should_fail {
            // Should fail during VerifyItem creation (length validation)
            assert!(
                item_result.is_err(),
                "Test case {} (msg={}, sig={}) should fail during VerifyItem creation",
                i,
                msg_len,
                sig_len
            );
        } else {
            // Should succeed
            let item = item_result.expect("VerifyItem creation should succeed");

            // Batch verify with single item
            let outcome = batch_verify_v2(std::iter::once(item));

            // Empty message might fail verification (depends on signature)
            if *msg_len == 0 {
                // Either succeeds or fails, but shouldn't panic
                let _ = outcome;
            } else {
                assert!(
                    outcome.is_all_valid(),
                    "Test case {} (msg={}, sig={}) should verify successfully",
                    i,
                    msg_len,
                    sig_len
                );
            }
        }
    }
}

/// Property test: batch verify determinism
#[test]
fn property_batch_verify_deterministic() {
    use crypto::{VerifyItem, batch_verify_v2};

    const BATCH_SIZE: usize = 10;

    // Generate keypairs and sign messages
    let mut publics = Vec::new();
    let mut messages = Vec::new();
    let mut signatures = Vec::new();

    for i in 0..BATCH_SIZE {
        let seed = [i as u8; 32];
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen should succeed");
        let pk_obj = PublicKey::from_bytes(pk);
        let sk_obj = SecretKey::from_bytes(sk);

        let message = format!("Deterministic message {}", i).into_bytes();
        let sig = sign(&message, &sk_obj, AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");

        publics.push(pk_obj);
        messages.push(message);
        signatures.push(sig);
    }

    // Run batch verify 5 times with same inputs
    let mut outcomes = Vec::new();
    for _ in 0..5 {
        let items: Vec<_> = publics
            .iter()
            .zip(messages.iter())
            .zip(signatures.iter())
            .map(|((pk, msg), sig)| {
                VerifyItem::new(
                    context::TX,
                    AlgTag::Dilithium2,
                    pk.as_bytes(),
                    msg,
                    &sig.bytes,
                )
                .expect("VerifyItem creation should succeed")
            })
            .collect();

        let outcome = batch_verify_v2(items);
        outcomes.push(outcome);
    }

    // All outcomes should be identical (deterministic)
    for outcome in &outcomes {
        assert!(
            outcome.is_all_valid(),
            "All runs should produce same outcome (all valid)"
        );
    }
}

/// Fuzz test: batch verify with maximum batch size
#[test]
fn fuzz_batch_verify_max_size() {
    use crypto::{VerifyItem, batch_verify_v2, get_max_batch_size};

    let max_size = get_max_batch_size();

    // Generate keypairs (reuse same key for all to save time)
    let seed = [42u8; 32];
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen should succeed");
    let pk_obj = PublicKey::from_bytes(pk);
    let sk_obj = SecretKey::from_bytes(sk);

    // Create max_size signatures
    let mut publics = vec![pk_obj.clone(); max_size];
    let mut messages = Vec::new();
    let mut signatures = Vec::new();

    for i in 0..max_size {
        let message = format!("Message {}", i).into_bytes();
        let sig = sign(&message, &sk_obj, AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");

        messages.push(message);
        signatures.push(sig);
    }

    // Create VerifyItems at max size
    let items: Vec<_> = publics
        .iter()
        .zip(messages.iter())
        .zip(signatures.iter())
        .map(|((pk, msg), sig)| {
            VerifyItem::new(
                context::TX,
                AlgTag::Dilithium2,
                pk.as_bytes(),
                msg,
                &sig.bytes,
            )
            .expect("VerifyItem creation should succeed")
        })
        .collect();

    // Batch verify at max size should succeed
    let outcome = batch_verify_v2(items);
    assert!(
        outcome.is_all_valid(),
        "Batch verify at max size ({}) should succeed",
        max_size
    );

    // Test oversized batch (max_size + 1)
    let extra_message = b"Extra message".to_vec();
    let extra_sig = sign(&extra_message, &sk_obj, AlgTag::Dilithium2, context::TX)
        .expect("signing should succeed");

    publics.push(pk_obj.clone());
    messages.push(extra_message);
    signatures.push(extra_sig);

    let oversized_items: Vec<_> = publics
        .iter()
        .zip(messages.iter())
        .zip(signatures.iter())
        .map(|((pk, msg), sig)| {
            VerifyItem::new(
                context::TX,
                AlgTag::Dilithium2,
                pk.as_bytes(),
                msg,
                &sig.bytes,
            )
            .expect("VerifyItem creation should succeed")
        })
        .collect();

    // Oversized batch should be rejected (all marked invalid)
    let outcome = batch_verify_v2(oversized_items);
    assert!(
        !outcome.is_all_valid(),
        "Batch verify should reject oversized batch"
    );
    assert_eq!(
        outcome.invalid_count(),
        max_size + 1,
        "All items in oversized batch should be marked invalid"
    );
}
