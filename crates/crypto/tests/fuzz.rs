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
