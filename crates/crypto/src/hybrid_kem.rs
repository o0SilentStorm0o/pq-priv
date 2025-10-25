//! Hybrid KEM (Key Encapsulation Mechanism) combining post-quantum and classical crypto.
//!
//! Implements **defense-in-depth** by combining:
//! - **Kyber512** (post-quantum, NIST ML-KEM) - protects against quantum adversaries
//! - **X25519** (classical ECDH) - protects against potential PQC breaks
//!
//! Security: Both components must be broken simultaneously for compromise.
//!
//! ## Construction
//!
//! ### Key Generation
//! ```text
//! (kyber_pk, kyber_sk) ← Kyber512.KeyGen()
//! (x25519_pk, x25519_sk) ← X25519.KeyGen()
//! hybrid_pk = (kyber_pk || x25519_pk)
//! hybrid_sk = (kyber_sk || x25519_sk)
//! ```
//!
//! ### Encapsulation (Sender)
//! ```text
//! (ct_kyber, ss_kyber) ← Kyber512.Encaps(kyber_pk)
//! (ephemeral_sk, ephemeral_pk) ← X25519.KeyGen()
//! ss_x25519 ← X25519.DH(ephemeral_sk, x25519_pk)
//! shared_secret ← BLAKE3(ss_kyber || ss_x25519 || DOMAIN_SEP)
//! ciphertext = (ct_kyber || ephemeral_pk)
//! ```
//!
//! ### Decapsulation (Receiver)
//! ```text
//! ss_kyber ← Kyber512.Decaps(kyber_sk, ct_kyber)
//! ss_x25519 ← X25519.DH(x25519_sk, ephemeral_pk)
//! shared_secret ← BLAKE3(ss_kyber || ss_x25519 || DOMAIN_SEP)
//! ```
//!
//! ## Security Properties
//!
//! - **Post-quantum security**: Kyber512 provides ~128-bit security against quantum attacks
//! - **Classical security**: X25519 provides ~128-bit security against classical attacks
//! - **Hybrid security**: Both must be broken for compromise (AND condition)
//! - **Non-interactive**: Public key can be distributed once, used for many encryptions
//!
//! ## Usage
//!
//! ```ignore
//! use crypto::hybrid_kem::{HybridKeypair, hybrid_encapsulate, hybrid_decapsulate};
//!
//! // Receiver generates keypair
//! let receiver_kp = HybridKeypair::generate();
//!
//! // Sender encapsulates shared secret
//! let (ciphertext, shared_secret) = hybrid_encapsulate(&receiver_kp.public_key);
//!
//! // Receiver decapsulates
//! let recovered_secret = hybrid_decapsulate(&receiver_kp.secret_key, &ciphertext)?;
//! assert_eq!(shared_secret, recovered_secret);
//! ```

use blake3::Hasher;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::MontgomeryPoint;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation tag for KDF.
const DOMAIN_SEP: &[u8] = b"PQPRIV-HYBRID-KEM-V1";

/// Hybrid public key (Kyber512 + X25519).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// Kyber512 public key (800 bytes).
    #[serde(with = "serde_bytes")]
    pub kyber_pk: Vec<u8>,
    
    /// X25519 public key (32 bytes).
    pub x25519_pk: [u8; 32],
}

/// Hybrid secret key (Kyber512 + X25519).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    /// Kyber512 secret key (1632 bytes).
    kyber_sk: Vec<u8>,
    
    /// X25519 secret key (32 bytes).
    x25519_sk: [u8; 32],
}

/// Hybrid keypair.
pub struct HybridKeypair {
    pub public_key: HybridPublicKey,
    pub secret_key: HybridSecretKey,
}

impl HybridKeypair {
    /// Generate a new hybrid keypair.
    pub fn generate() -> Self {
        // Generate Kyber512 keypair
        let (kyber_pk, kyber_sk) = kyber512::keypair();
        
        // Generate X25519 keypair using curve25519-dalek
        let mut scalar_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut scalar_bytes);
        let x25519_sk = Scalar::from_bytes_mod_order(scalar_bytes);
        let x25519_pk = (&x25519_sk * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
            .to_montgomery()
            .to_bytes();
        
        Self {
            public_key: HybridPublicKey {
                kyber_pk: kyber_pk.as_bytes().to_vec(),
                x25519_pk,
            },
            secret_key: HybridSecretKey {
                kyber_sk: kyber_sk.as_bytes().to_vec(),
                x25519_sk: x25519_sk.to_bytes(),
            },
        }
    }
}

/// Hybrid KEM ciphertext (Kyber512 CT + X25519 ephemeral PK).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Kyber512 ciphertext (768 bytes).
    #[serde(with = "serde_bytes")]
    pub kyber_ct: Vec<u8>,
    
    /// X25519 ephemeral public key (32 bytes).
    pub x25519_ephemeral_pk: [u8; 32],
}

/// Encapsulate a shared secret using hybrid KEM.
///
/// Returns (ciphertext, 32-byte shared secret).
pub fn hybrid_encapsulate(public_key: &HybridPublicKey) -> (HybridCiphertext, [u8; 32]) {
    // 1. Kyber512 encapsulation
    let kyber_pk = kyber512::PublicKey::from_bytes(&public_key.kyber_pk)
        .expect("valid Kyber public key");
    let (kyber_ss, kyber_ct) = kyber512::encapsulate(&kyber_pk);
    
    // 2. X25519 ECDH with ephemeral key (using curve25519-dalek)
    let mut ephemeral_scalar_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_scalar_bytes);
    let ephemeral_sk = Scalar::from_bytes_mod_order(ephemeral_scalar_bytes);
    let ephemeral_pk = (&ephemeral_sk * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
        .to_montgomery()
        .to_bytes();
    
    // Perform DH: ephemeral_sk * receiver_pk
    let receiver_pk = MontgomeryPoint(public_key.x25519_pk);
    let x25519_ss_point = ephemeral_sk * receiver_pk;
    let x25519_ss = x25519_ss_point.to_bytes();
    
    // 3. Combine shared secrets via KDF
    let shared_secret = kdf(kyber_ss.as_bytes(), &x25519_ss);
    
    let ciphertext = HybridCiphertext {
        kyber_ct: kyber_ct.as_bytes().to_vec(),
        x25519_ephemeral_pk: ephemeral_pk,
    };
    
    (ciphertext, shared_secret)
}

/// Decapsulate a shared secret using hybrid KEM.
///
/// Returns the 32-byte shared secret.
pub fn hybrid_decapsulate(
    secret_key: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
) -> Result<[u8; 32], &'static str> {
    // 1. Kyber512 decapsulation
    let kyber_sk = kyber512::SecretKey::from_bytes(&secret_key.kyber_sk)
        .map_err(|_| "invalid Kyber secret key")?;
    let kyber_ct = kyber512::Ciphertext::from_bytes(&ciphertext.kyber_ct)
        .map_err(|_| "invalid Kyber ciphertext")?;
    let kyber_ss = kyber512::decapsulate(&kyber_ct, &kyber_sk);
    
    // 2. X25519 ECDH with ephemeral public key (using curve25519-dalek)
    let receiver_sk = Scalar::from_bytes_mod_order(secret_key.x25519_sk);
    let ephemeral_pk = MontgomeryPoint(ciphertext.x25519_ephemeral_pk);
    
    // Perform DH: receiver_sk * ephemeral_pk
    let x25519_ss_point = receiver_sk * ephemeral_pk;
    let x25519_ss = x25519_ss_point.to_bytes();
    
    // 3. Combine shared secrets via KDF
    let shared_secret = kdf(kyber_ss.as_bytes(), &x25519_ss);
    
    Ok(shared_secret)
}

/// Key derivation function combining both shared secrets.
///
/// KDF(ss_kyber || ss_x25519) = BLAKE3(ss_kyber || ss_x25519 || DOMAIN_SEP)[0..32]
fn kdf(kyber_ss: &[u8], x25519_ss: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(kyber_ss);
    hasher.update(x25519_ss);
    hasher.update(DOMAIN_SEP);
    
    let hash = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash.as_bytes()[0..32]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let kp = HybridKeypair::generate();
        
        let (ct, ss_sender) = hybrid_encapsulate(&kp.public_key);
        let ss_receiver = hybrid_decapsulate(&kp.secret_key, &ct).unwrap();
        
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn test_different_encapsulations_different_secrets() {
        let kp = HybridKeypair::generate();
        
        let (_, ss1) = hybrid_encapsulate(&kp.public_key);
        let (_, ss2) = hybrid_encapsulate(&kp.public_key);
        
        // Different encapsulations should produce different shared secrets
        // (due to random ephemeral keys)
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_shared_secret_length() {
        let kp = HybridKeypair::generate();
        let (_, ss) = hybrid_encapsulate(&kp.public_key);
        
        assert_eq!(ss.len(), 32);
    }

    #[test]
    fn test_ciphertext_structure() {
        let kp = HybridKeypair::generate();
        let (ct, _) = hybrid_encapsulate(&kp.public_key);
        
        // Kyber512 ciphertext is 768 bytes
        assert_eq!(ct.kyber_ct.len(), 768);
        
        // X25519 ephemeral PK is 32 bytes
        assert_eq!(ct.x25519_ephemeral_pk.len(), 32);
    }

    #[test]
    fn test_invalid_ciphertext_fails() {
        let kp = HybridKeypair::generate();
        
        let mut bad_ct = HybridCiphertext {
            kyber_ct: vec![0u8; 768], // Invalid ciphertext
            x25519_ephemeral_pk: [0u8; 32],
        };
        
        // Should fail to decapsulate corrupted ciphertext
        let _result = hybrid_decapsulate(&kp.secret_key, &bad_ct);
        // Note: Kyber512 may still return a shared secret even with invalid CT
        // (due to implicit rejection), but it won't match the sender's secret
        
        // Verify that corrupting CT changes the output
        let (real_ct, real_ss) = hybrid_encapsulate(&kp.public_key);
        bad_ct.kyber_ct = real_ct.kyber_ct.clone();
        bad_ct.kyber_ct[0] ^= 1; // Flip one bit
        
        let corrupted_ss = hybrid_decapsulate(&kp.secret_key, &bad_ct).unwrap();
        assert_ne!(corrupted_ss, real_ss);
    }
}
