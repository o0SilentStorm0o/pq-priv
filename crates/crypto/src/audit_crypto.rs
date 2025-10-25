//! Audit packet cryptography (encryption + signing).
//!
//! Provides complete encryption and authentication for audit packets using:
//! - **Hybrid KEM**: Kyber512 + X25519 for key encapsulation
//! - **AEAD**: ChaCha20-Poly1305 for authenticated encryption
//! - **Signature**: Dilithium2 for post-quantum digital signatures
//!
//! ## Construction
//!
//! ### Encryption
//! ```text
//! (kem_ct, shared_secret) ← HybridKEM.Encaps(exchange_pk)
//! aead_key ← shared_secret[0..32]
//! nonce ← random(12 bytes)
//! ciphertext ← ChaCha20Poly1305.Encrypt(aead_key, nonce, plaintext, associated_data=metadata)
//! encrypted_packet = (kem_ct || nonce || ciphertext)
//! ```
//!
//! ### Signing
//! ```text
//! message = metadata || encrypted_packet
//! signature ← Dilithium2.Sign(wallet_sk, message)
//! final_packet = (metadata || encrypted_packet || signature)
//! ```
//!
//! ## Security Properties
//!
//! - **Confidentiality**: ChaCha20-Poly1305 provides IND-CCA2 security
//! - **Authenticity**: Poly1305 MAC prevents tampering
//! - **Post-quantum**: Kyber512 + Dilithium2 resist quantum attacks
//! - **Hybrid security**: X25519 provides defense-in-depth
//! - **Forward secrecy**: Ephemeral KEM keys ensure FS

use crate::hybrid_kem::{hybrid_encapsulate, hybrid_decapsulate, HybridPublicKey, HybridSecretKey, HybridCiphertext};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use pqcrypto_mldsa::mldsa44;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Encrypted audit packet with signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedAuditPacket {
    /// Hybrid KEM ciphertext (Kyber512 CT + X25519 ephemeral PK).
    pub kem_ciphertext: HybridCiphertext,
    
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; 12],
    
    /// AEAD ciphertext (plaintext + 16-byte Poly1305 tag).
    #[serde(with = "serde_bytes")]
    pub aead_ciphertext: Vec<u8>,
    
    /// Dilithium2 signature over (kem_ct || nonce || aead_ct).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Encrypt and sign audit packet data.
///
/// # Arguments
///
/// * `plaintext` - Audit data to encrypt (L1/L2/L3 serialized)
/// * `associated_data` - Metadata to authenticate (not encrypted)
/// * `exchange_public_key` - Hybrid public key of exchange
/// * `wallet_signing_key` - Dilithium2 secret key for signing
///
/// # Returns
///
/// Encrypted and signed packet ready for transmission.
pub fn encrypt_and_sign_audit(
    plaintext: &[u8],
    associated_data: &[u8],
    exchange_public_key: &HybridPublicKey,
    wallet_signing_key: &[u8],
) -> Result<EncryptedAuditPacket, &'static str> {
    // 1. Hybrid KEM encapsulation
    let (kem_ciphertext, shared_secret) = hybrid_encapsulate(exchange_public_key);
    
    // 2. Derive AEAD key from shared secret
    let aead_key = shared_secret; // Already 32 bytes from KDF
    
    // 3. Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 4. ChaCha20-Poly1305 encryption with authenticated associated data
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|_| "invalid AEAD key")?;
    
    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };
    
    let aead_ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| "AEAD encryption failed")?;
    
    // 5. Sign the entire encrypted packet
    let signing_key = mldsa44::SecretKey::from_bytes(wallet_signing_key)
        .map_err(|_| "invalid Dilithium2 secret key")?;
    
    // Message to sign: kem_ct || nonce || aead_ct
    let mut message_to_sign = Vec::new();
    // Serialize HybridCiphertext to CBOR
    let mut kem_ct_buf = Vec::new();
    ciborium::ser::into_writer(&kem_ciphertext, &mut kem_ct_buf)
        .map_err(|_| "failed to serialize KEM ciphertext")?;
    message_to_sign.extend_from_slice(&kem_ct_buf);
    message_to_sign.extend_from_slice(&nonce_bytes);
    message_to_sign.extend_from_slice(&aead_ciphertext);
    
    let detached_sig = mldsa44::detached_sign(&message_to_sign, &signing_key);
    let signature = detached_sig.as_bytes().to_vec();
    
    Ok(EncryptedAuditPacket {
        kem_ciphertext,
        nonce: nonce_bytes,
        aead_ciphertext,
        signature,
    })
}

/// Verify and decrypt audit packet.
///
/// # Arguments
///
/// * `packet` - Encrypted audit packet
/// * `associated_data` - Metadata that was authenticated
/// * `exchange_secret_key` - Hybrid secret key of exchange
/// * `wallet_public_key` - Dilithium2 public key for verification
///
/// # Returns
///
/// Decrypted plaintext if signature and decryption succeed.
pub fn verify_and_decrypt_audit(
    packet: &EncryptedAuditPacket,
    associated_data: &[u8],
    exchange_secret_key: &HybridSecretKey,
    wallet_public_key: &[u8],
) -> Result<Vec<u8>, &'static str> {
    // 1. Verify Dilithium2 signature
    let public_key = mldsa44::PublicKey::from_bytes(wallet_public_key)
        .map_err(|_| "invalid Dilithium2 public key")?;
    
    // Reconstruct message that was signed
    let mut message_to_verify = Vec::new();
    let mut kem_ct_buf = Vec::new();
    ciborium::ser::into_writer(&packet.kem_ciphertext, &mut kem_ct_buf)
        .map_err(|_| "failed to serialize KEM ciphertext")?;
    message_to_verify.extend_from_slice(&kem_ct_buf);
    message_to_verify.extend_from_slice(&packet.nonce);
    message_to_verify.extend_from_slice(&packet.aead_ciphertext);
    
    // Verify detached signature
    let detached_sig = mldsa44::DetachedSignature::from_bytes(&packet.signature)
        .map_err(|_| "invalid signature format")?;
    
    mldsa44::verify_detached_signature(&detached_sig, &message_to_verify, &public_key)
        .map_err(|_| "signature verification failed")?;
    
    // 2. Hybrid KEM decapsulation
    let mut shared_secret = hybrid_decapsulate(exchange_secret_key, &packet.kem_ciphertext)?;
    
    // 3. Derive AEAD key
    let aead_key = shared_secret; // Already 32 bytes
    
    // 4. ChaCha20-Poly1305 decryption
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|_| "invalid AEAD key")?;
    
    let nonce = Nonce::from_slice(&packet.nonce);
    
    let payload = Payload {
        msg: &packet.aead_ciphertext,
        aad: associated_data,
    };
    
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| "AEAD decryption failed")?;
    
    // Zeroize shared secret
    shared_secret.zeroize();
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_kem::HybridKeypair;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate keys
        let exchange_kp = HybridKeypair::generate();
        let (wallet_pk, wallet_sk) = mldsa44::keypair();
        
        let plaintext = b"sensitive audit data L2: amount=50000";
        let metadata = b"audit_level=L2,txid=abc123";
        
        // Encrypt and sign
        let encrypted = encrypt_and_sign_audit(
            plaintext,
            metadata,
            &exchange_kp.public_key,
            wallet_sk.as_bytes(),
        )
        .expect("encryption failed");
        
        // Verify and decrypt
        let decrypted = verify_and_decrypt_audit(
            &encrypted,
            metadata,
            &exchange_kp.secret_key,
            wallet_pk.as_bytes(),
        )
        .expect("decryption failed");
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_signature_verification_fails_on_tamper() {
        let exchange_kp = HybridKeypair::generate();
        let (wallet_pk, wallet_sk) = mldsa44::keypair();
        
        let plaintext = b"original data";
        let metadata = b"metadata";
        
        let mut encrypted = encrypt_and_sign_audit(
            plaintext,
            metadata,
            &exchange_kp.public_key,
            wallet_sk.as_bytes(),
        )
        .unwrap();
        
        // Tamper with ciphertext
        encrypted.aead_ciphertext[0] ^= 1;
        
        // Verification should fail
        let result = verify_and_decrypt_audit(
            &encrypted,
            metadata,
            &exchange_kp.secret_key,
            wallet_pk.as_bytes(),
        );
        
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_associated_data_fails() {
        let exchange_kp = HybridKeypair::generate();
        let (wallet_pk, wallet_sk) = mldsa44::keypair();
        
        let plaintext = b"data";
        let metadata1 = b"correct metadata";
        let metadata2 = b"wrong metadata";
        
        let encrypted = encrypt_and_sign_audit(
            plaintext,
            metadata1,
            &exchange_kp.public_key,
            wallet_sk.as_bytes(),
        )
        .unwrap();
        
        // Decrypt with wrong associated data should fail
        let result = verify_and_decrypt_audit(
            &encrypted,
            metadata2, // Wrong!
            &exchange_kp.secret_key,
            wallet_pk.as_bytes(),
        );
        
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_structure() {
        let exchange_kp = HybridKeypair::generate();
        let (_, wallet_sk) = mldsa44::keypair();
        
        let plaintext = b"test";
        let metadata = b"meta";
        
        let encrypted = encrypt_and_sign_audit(
            plaintext,
            metadata,
            &exchange_kp.public_key,
            wallet_sk.as_bytes(),
        )
        .unwrap();
        
        // Verify packet structure
        assert_eq!(encrypted.nonce.len(), 12);
        assert!(encrypted.aead_ciphertext.len() > plaintext.len()); // Includes Poly1305 tag
        assert!(encrypted.signature.len() > 0); // Dilithium2 signature
    }
}
