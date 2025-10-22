//! Integration tests for cryptographic primitives.
//!
//! These tests verify end-to-end workflows including key generation,
//! signing, verification, and cross-algorithm compatibility.

use crypto::{
    AlgTag, CryptoError, Dilithium2Scheme, KeyMaterial, PublicKey, SecretKey, Signature,
    SignatureScheme, sign, verify,
};

#[cfg(feature = "dev_stub_signing")]
use crypto::Ed25519Stub;

/// Test complete workflow: keygen → sign → verify for Dilithium2
#[test]
fn dilithium2_end_to_end_workflow() {
    // Step 1: Generate Dilithium2 keypair directly
    let seed = [42u8; 32];
    let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed)
        .expect("Dilithium2 keygen should succeed");
    
    let public_key = PublicKey::from_bytes(pk_bytes.clone());
    let secret_key = SecretKey::from_bytes(sk_bytes);
    
    // Step 2: Generate a second keypair for negative tests
    let (pk2_bytes, _) = Dilithium2Scheme::keygen_from_seed(&[99u8; 32])
        .expect("Second keygen should succeed");
    let wrong_public_key = PublicKey::from_bytes(pk2_bytes);
    
    // Step 3: Sign message with Dilithium2
    let message = b"Transfer 100 coins to Alice";
    let sig = sign(message, &secret_key, AlgTag::Dilithium2)
        .expect("Dilithium2 signing should succeed");
    
    // Step 4: Verify signature
    assert_eq!(sig.alg, AlgTag::Dilithium2);
    verify(message, &public_key, &sig)
        .expect("Signature should verify successfully");
    
    // Step 5: Verify rejection of wrong key
    assert!(verify(message, &wrong_public_key, &sig).is_err(),
        "Signature should not verify with wrong public key");
    
    // Step 6: Verify rejection of modified message
    let modified_message = b"Transfer 999 coins to Alice";
    assert!(verify(modified_message, &public_key, &sig).is_err(),
        "Signature should not verify with modified message");
}

/// Test that Ed25519 and Dilithium2 can coexist
#[cfg(feature = "dev_stub_signing")]
#[test]
fn cross_algorithm_compatibility() {
    let km = KeyMaterial::random();
    let spend = km.derive_spend_keypair(0);
    let message = b"Cross-algorithm test message";
    
    // Sign with Ed25519
    let ed25519_sig = sign(message, &spend.secret, AlgTag::Ed25519)
        .expect("Ed25519 signing should succeed");
    assert_eq!(ed25519_sig.alg, AlgTag::Ed25519);
    
    // Verify Ed25519 signature
    verify(message, &spend.public, &ed25519_sig)
        .expect("Ed25519 signature should verify");
    
    // Generate Dilithium2 keys
    let (dilithium_pk, dilithium_sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32])
        .expect("Dilithium2 keygen should succeed");
    let dilithium_public = PublicKey::from_bytes(dilithium_pk);
    let dilithium_secret = SecretKey::from_bytes(dilithium_sk);
    
    // Sign with Dilithium2
    let dilithium_sig = sign(message, &dilithium_secret, AlgTag::Dilithium2)
        .expect("Dilithium2 signing should succeed");
    assert_eq!(dilithium_sig.alg, AlgTag::Dilithium2);
    
    // Verify Dilithium2 signature
    verify(message, &dilithium_public, &dilithium_sig)
        .expect("Dilithium2 signature should verify");
    
    // Cross-verify should fail (Ed25519 sig with Dilithium2 key)
    assert!(verify(message, &dilithium_public, &ed25519_sig).is_err(),
        "Ed25519 signature should not verify with Dilithium2 key");
    
    // Cross-verify should fail (Dilithium2 sig with Ed25519 key)
    assert!(verify(message, &spend.public, &dilithium_sig).is_err(),
        "Dilithium2 signature should not verify with Ed25519 key");
}

/// Test signature scheme trait directly for Dilithium2
#[test]
fn dilithium2_trait_implementation() {
    // Test constants
    assert_eq!(Dilithium2Scheme::ALG, AlgTag::Dilithium2);
    assert_eq!(Dilithium2Scheme::NAME, "Dilithium2");
    assert_eq!(Dilithium2Scheme::PUBLIC_KEY_BYTES, 1312);
    assert_eq!(Dilithium2Scheme::SIGNATURE_BYTES, 2420);
    
    // Test keygen
    let seed = [0x42; 32];
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed)
        .expect("keygen should succeed");
    
    assert_eq!(pk.len(), Dilithium2Scheme::PUBLIC_KEY_BYTES);
    assert_eq!(sk.len(), Dilithium2Scheme::SECRET_KEY_BYTES);
    
    // Test signing
    let message = b"Trait implementation test";
    let sig = Dilithium2Scheme::sign(&sk, message)
        .expect("sign should succeed");
    assert_eq!(sig.len(), Dilithium2Scheme::SIGNATURE_BYTES);
    
    // Test verification
    assert!(Dilithium2Scheme::verify(&pk, message, &sig),
        "signature should verify");
    
    // Test rejection of invalid inputs
    let empty_key = vec![];
    assert!(Dilithium2Scheme::sign(&empty_key, message).is_err(),
        "signing with invalid key should fail");
    assert!(!Dilithium2Scheme::verify(&empty_key, message, &sig),
        "verify with invalid key should return false");
}

/// Test multiple sequential signatures (randomness check)
#[test]
fn dilithium2_multiple_signatures() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[99; 32])
        .expect("keygen should succeed");
    
    let message = b"Same message, multiple times";
    let mut signatures = Vec::new();
    
    // Generate 10 signatures of the same message
    for _ in 0..10 {
        let sig = Dilithium2Scheme::sign(&sk, message)
            .expect("sign should succeed");
        signatures.push(sig);
    }
    
    // All signatures should verify
    for sig in &signatures {
        assert!(Dilithium2Scheme::verify(&pk, message, sig),
            "all signatures should verify");
    }
    
    // Note: Dilithium2 may produce different signatures each time (randomized)
    // but we don't enforce this as it depends on the implementation
}

/// Test signature verification with corrupted data
#[test]
fn dilithium2_corruption_detection() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[77; 32])
        .expect("keygen should succeed");
    
    let message = b"Original message";
    let sig = Dilithium2Scheme::sign(&sk, message)
        .expect("sign should succeed");
    
    // Corrupt each byte of the signature one at a time
    for i in 0..sig.len().min(100) { // Test first 100 bytes for speed
        let mut corrupted = sig.clone();
        corrupted[i] ^= 0xFF;
        
        assert!(!Dilithium2Scheme::verify(&pk, message, &corrupted),
            "corrupted signature at byte {} should not verify", i);
    }
    
    // Corrupt the public key
    for i in 0..pk.len().min(50) {
        let mut corrupted_pk = pk.clone();
        corrupted_pk[i] ^= 0xFF;
        
        assert!(!Dilithium2Scheme::verify(&corrupted_pk, message, &sig),
            "signature should not verify with corrupted public key at byte {}", i);
    }
}

/// Test key derivation determinism
#[test]
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
    assert_eq!(spend1.public.as_bytes(), spend2.public.as_bytes(),
        "public keys should be deterministic");
    assert_eq!(spend1.secret.as_bytes(), spend2.secret.as_bytes(),
        "secret keys should be deterministic");
    
    assert_eq!(scan1.public.as_bytes(), scan2.public.as_bytes(),
        "scan public keys should be deterministic");
    assert_eq!(scan1.secret.as_bytes(), scan2.secret.as_bytes(),
        "scan secret keys should be deterministic");
    
    // Different indices should produce different keys
    let spend_index_0 = km1.derive_spend_keypair(0);
    let spend_index_1 = km1.derive_spend_keypair(1);
    
    assert_ne!(spend_index_0.public.as_bytes(), spend_index_1.public.as_bytes(),
        "different indices should produce different keys");
}

/// Test large message signing and verification
#[test]
fn dilithium2_large_message() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[123; 32])
        .expect("keygen should succeed");
    
    // Test with messages of various sizes
    let sizes = vec![0, 1, 100, 1024, 10_000, 100_000, 1_000_000];
    
    for size in sizes {
        let message = vec![0x42u8; size];
        
        let sig = Dilithium2Scheme::sign(&sk, &message)
            .expect("signing large message should succeed");
        
        assert!(Dilithium2Scheme::verify(&pk, &message, &sig),
            "large message ({} bytes) should verify", size);
        
        // Modify one byte and ensure it fails
        if size > 0 {
            let mut modified = message.clone();
            modified[size / 2] ^= 0xFF;
            
            assert!(!Dilithium2Scheme::verify(&pk, &modified, &sig),
                "modified large message should not verify");
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
    match sign(message, &spend.secret, AlgTag::Dilithium3) {
        Err(CryptoError::UnsupportedAlg(0x02)) => {}, // Expected
        other => panic!("Expected UnsupportedAlg error, got {:?}", other),
    }
    
    // Dilithium5 not yet implemented
    match sign(message, &spend.secret, AlgTag::Dilithium5) {
        Err(CryptoError::UnsupportedAlg(0x03)) => {}, // Expected
        other => panic!("Expected UnsupportedAlg error, got {:?}", other),
    }
    
    // SPHINCS+ not yet implemented
    match sign(message, &spend.secret, AlgTag::SphincsPlus) {
        Err(CryptoError::UnsupportedAlg(0x10)) => {}, // Expected
        other => panic!("Expected UnsupportedAlg error, got {:?}", other),
    }
}

/// Test signature serialization/deserialization
#[test]
fn signature_serialization() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[55; 32])
        .expect("keygen should succeed");
    
    let message = b"Serialization test";
    let sig = Dilithium2Scheme::sign(&sk, message)
        .expect("sign should succeed");
    
    // Create signature object
    let signature = Signature::new(AlgTag::Dilithium2, sig.clone());
    
    // Serialize with serde_json
    let json = serde_json::to_string(&signature)
        .expect("signature should serialize");
    
    // Deserialize
    let deserialized: Signature = serde_json::from_str(&json)
        .expect("signature should deserialize");
    
    assert_eq!(deserialized.alg, AlgTag::Dilithium2);
    assert_eq!(deserialized.bytes, sig);
    
    // Verify deserialized signature works
    let pk_obj = PublicKey::from_bytes(pk);
    verify(message, &pk_obj, &deserialized)
        .expect("deserialized signature should verify");
}

/// Benchmark-style test: sign and verify 100 messages
#[test]
fn dilithium2_throughput_test() {
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32])
        .expect("keygen should succeed");
    
    let count = 100;
    let mut signatures = Vec::with_capacity(count);
    
    // Sign 100 messages
    let sign_start = std::time::Instant::now();
    for i in 0..count {
        let message = format!("Message number {}", i);
        let sig = Dilithium2Scheme::sign(&sk, message.as_bytes())
            .expect("sign should succeed");
        signatures.push((message, sig));
    }
    let sign_duration = sign_start.elapsed();
    
    // Verify 100 signatures
    let verify_start = std::time::Instant::now();
    for (message, sig) in &signatures {
        assert!(Dilithium2Scheme::verify(&pk, message.as_bytes(), sig),
            "signature should verify");
    }
    let verify_duration = verify_start.elapsed();
    
    println!("\n=== Dilithium2 Throughput Test ===");
    println!("Signed {} messages in {:?}", count, sign_duration);
    println!("Average signing time: {:?}", sign_duration / count as u32);
    println!("Verified {} signatures in {:?}", count, verify_duration);
    println!("Average verification time: {:?}", verify_duration / count as u32);
    println!("==================================\n");
    
    // Basic sanity checks (these are slow reference implementations)
    assert!(sign_duration.as_millis() < 10_000, "signing should complete in reasonable time");
    assert!(verify_duration.as_millis() < 10_000, "verification should complete in reasonable time");
}
