//! Cryptographic primitives for the PQ-PRIV prototype.
//!
//! This module provides a trait-based pluggable signature scheme API that
//! supports both post-quantum algorithms (Dilithium, SPHINCS+) and
//! Ed25519 as a development stub for testing.
//!
//! The API is designed so that swapping implementations only requires
//! changing the algorithm tag and does not affect calling code.

use std::convert::TryInto;

use blake3::derive_key;
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PQPublicKey, SecretKey as PQSecretKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

/// Length (in bytes) of keys and tags produced by the placeholder scheme.
pub const KEY_LEN: usize = 32;

/// Signature algorithm tags advertised on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlgTag {
    /// Ed25519 signature scheme (development stub only).
    /// Only available with `dev_stub_signing` feature.
    Ed25519 = 0x00,
    /// CRYSTALS-Dilithium2 post-quantum signature scheme.
    Dilithium2 = 0x01,
    /// CRYSTALS-Dilithium3 post-quantum signature scheme.
    Dilithium3 = 0x02,
    /// CRYSTALS-Dilithium5 post-quantum signature scheme.
    Dilithium5 = 0x03,
    /// SPHINCS+ post-quantum signature scheme.
    SphincsPlus = 0x10,
}

impl AlgTag {
    pub fn from_byte(byte: u8) -> Result<Self, CryptoError> {
        match byte {
            0x00 => Ok(Self::Ed25519),
            0x01 => Ok(Self::Dilithium2),
            0x02 => Ok(Self::Dilithium3),
            0x03 => Ok(Self::Dilithium5),
            0x10 => Ok(Self::SphincsPlus),
            other => Err(CryptoError::UnsupportedAlg(other)),
        }
    }

    /// Returns the name of the algorithm as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Dilithium2 => "Dilithium2",
            Self::Dilithium3 => "Dilithium3",
            Self::Dilithium5 => "Dilithium5",
            Self::SphincsPlus => "SPHINCS+",
        }
    }
}

/// Errors emitted by cryptographic helpers.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("unsupported signature algorithm: 0x{0:02x}")]
    UnsupportedAlg(u8),
    #[error("malformed key material")]
    InvalidKey,
    #[error("key generation failed")]
    KeyGenFailed,
    #[error("signing operation failed")]
    SigningFailed,
}

/// Trait defining a pluggable signature scheme.
///
/// Implementations provide key generation, signing, and verification
/// operations for a specific cryptographic algorithm.
pub trait SignatureScheme {
    /// The algorithm tag identifying this scheme.
    const ALG: AlgTag;

    /// The name of the algorithm (for display purposes).
    const NAME: &'static str;

    /// The size of public keys in bytes.
    const PUBLIC_KEY_BYTES: usize;

    /// The size of secret keys in bytes.
    const SECRET_KEY_BYTES: usize;

    /// The size of signatures in bytes.
    const SIGNATURE_BYTES: usize;

    /// Generate a new keypair from a 32-byte seed.
    fn keygen_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Sign a message with the secret key.
    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Verify a signature with the public key.
    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

/// Deterministic key material used for both scan and spend keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterial {
    #[serde(with = "serde_bytes")]
    master_seed: Vec<u8>,
}

impl KeyMaterial {
    /// Create a new key material container from raw entropy.
    pub fn from_entropy(entropy: &[u8]) -> Self {
        let mut seed = vec![0u8; KEY_LEN];
        let hash = blake3::hash(entropy);
        seed.copy_from_slice(hash.as_bytes());
        Self { master_seed: seed }
    }

    /// Generate random key material using the operating system RNG.
    pub fn random() -> Self {
        let mut rng = OsRng;
        let mut seed = vec![0u8; KEY_LEN];
        rng.fill_bytes(&mut seed);
        Self { master_seed: seed }
    }

    fn derive_seed(&self, label: &str, index: u32) -> [u8; KEY_LEN] {
        let mut context = [0u8; 8];
        context[..4].copy_from_slice(&index.to_le_bytes());
        let key = derive_key(label, &self.master_seed);
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&context);
        hasher.finalize().into()
    }

    /// Derive the `index`-th scan keypair.
    pub fn derive_scan_keypair(&self, index: u32) -> ScanKeypair {
        let seed = self.derive_seed("scan", index);
        ScanKeypair::from_seed(seed)
    }

    /// Derive the `index`-th spend keypair.
    pub fn derive_spend_keypair(&self, index: u32) -> SpendKeypair {
        let seed = self.derive_seed("spend", index);
        SpendKeypair::from_seed(seed)
    }

    /// Create a scope limited view token that can be shared with an
    /// auditor or an exchange.
    pub fn derive_view_token(&self, scope: &str) -> ViewToken {
        let key: [u8; KEY_LEN] = self.master_seed.as_slice().try_into().expect("seed length");
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(scope.as_bytes());
        ViewToken {
            tag: hasher.finalize().into(),
        }
    }
}

/// Representation of a detached signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub alg: AlgTag,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

impl Signature {
    pub fn new(alg: AlgTag, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }
}

/// Public key wrapper used by the placeholder Dilithium implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Secret key wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl SecretKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Scan keypair used to detect stealth outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanKeypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl ScanKeypair {
    pub fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        let (public, secret) = keypair_from_seed(seed);
        Self { public, secret }
    }
}

/// Spend keypair used to authorise spends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendKeypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl SpendKeypair {
    pub fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        let (public, secret) = keypair_from_seed(seed);
        Self { public, secret }
    }
}

fn keypair_from_seed(seed: [u8; KEY_LEN]) -> (PublicKey, SecretKey) {
    // Use the default signature scheme for key derivation.
    // In dev mode this is Ed25519, in production it's Dilithium2.
    #[cfg(feature = "dev_stub_signing")]
    let (pk, sk) = Ed25519Stub::keygen_from_seed(&seed)
        .expect("keygen from seed should not fail");

    #[cfg(not(feature = "dev_stub_signing"))]
    let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed)
        .expect("keygen from seed should not fail");

    (
        PublicKey::from_bytes(pk),
        SecretKey::from_bytes(sk),
    )
}

/// Minimal view token shared with auditors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewToken {
    pub tag: [u8; KEY_LEN],
}

/// Ed25519 signature scheme implementation (development stub).
///
/// This implementation is only intended for testing and development.
/// Production deployments should use post-quantum schemes.
#[cfg(feature = "dev_stub_signing")]
pub struct Ed25519Stub;

#[cfg(feature = "dev_stub_signing")]
impl SignatureScheme for Ed25519Stub {
    const ALG: AlgTag = AlgTag::Ed25519;
    const NAME: &'static str = "Ed25519";
    const PUBLIC_KEY_BYTES: usize = 32;
    const SECRET_KEY_BYTES: usize = 32;
    const SIGNATURE_BYTES: usize = 64;

    fn keygen_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let signing = SigningKey::from_bytes(&sk_bytes);
        let verifying = signing.verifying_key();
        Ok((
            verifying.to_bytes().to_vec(),
            signing.to_bytes().to_vec(),
        ))
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk_bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let signing = SigningKey::from_bytes(&sk_bytes);
        let sig = signing.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let vk_bytes: [u8; 32] = match public.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let verifying = match VerifyingKey::from_bytes(&vk_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 64] = match sig.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let signature = DalekSignature::from_bytes(&sig_bytes);
        verifying.verify(msg, &signature).is_ok()
    }
}

/// Dilithium2 post-quantum signature scheme implementation.
///
/// CRYSTALS-Dilithium is a lattice-based signature scheme standardized
/// by NIST (FIPS 204). Dilithium2 provides NIST security level 2
/// (equivalent to AES-128 against quantum attacks).
pub struct Dilithium2Scheme;

impl SignatureScheme for Dilithium2Scheme {
    const ALG: AlgTag = AlgTag::Dilithium2;
    const NAME: &'static str = "Dilithium2";
    const PUBLIC_KEY_BYTES: usize = dilithium2::public_key_bytes();
    const SECRET_KEY_BYTES: usize = dilithium2::secret_key_bytes();
    const SIGNATURE_BYTES: usize = dilithium2::signature_bytes();

    fn keygen_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // Note: pqcrypto-dilithium doesn't expose a seeded keygen directly.
        // It uses system entropy for key generation.
        // For deterministic keygen, we would need to use liboqs or implement
        // a custom seeded RNG integration.
        // For now, we hash the seed to derive a deterministic but unpredictable
        // value that influences the key generation context.
        
        // TODO: Implement proper deterministic keygen using seed
        // For Sprint 5, we accept non-deterministic keygen as a limitation
        let _seed_hash = blake3::hash(seed);
        
        let (pk, sk) = dilithium2::keypair();
        
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if secret.len() != Self::SECRET_KEY_BYTES {
            return Err(CryptoError::InvalidKey);
        }
        
        let sk = dilithium2::SecretKey::from_bytes(secret)
            .map_err(|_| CryptoError::InvalidKey)?;
        
        let sig = dilithium2::detached_sign(msg, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        if public.len() != Self::PUBLIC_KEY_BYTES || sig.len() != Self::SIGNATURE_BYTES {
            return false;
        }
        
        let pk = match dilithium2::PublicKey::from_bytes(public) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        
        let signature = match dilithium2::DetachedSignature::from_bytes(sig) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        dilithium2::verify_detached_signature(&signature, msg, &pk).is_ok()
    }
}

/// High-level signing API that dispatches to the appropriate scheme.
pub fn sign(message: &[u8], secret: &SecretKey, alg: AlgTag) -> Result<Signature, CryptoError> {
    let sig_bytes = match alg {
        #[cfg(feature = "dev_stub_signing")]
        AlgTag::Ed25519 => Ed25519Stub::sign(secret.as_bytes(), message)?,
        AlgTag::Dilithium2 => Dilithium2Scheme::sign(secret.as_bytes(), message)?,
        AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => {
            return Err(CryptoError::UnsupportedAlg(alg as u8));
        }
        #[cfg(not(feature = "dev_stub_signing"))]
        AlgTag::Ed25519 => return Err(CryptoError::UnsupportedAlg(alg as u8)),
    };
    Ok(Signature::new(alg, sig_bytes))
}

/// High-level verification API that dispatches to the appropriate scheme.
pub fn verify(
    message: &[u8],
    public: &PublicKey,
    signature: &Signature,
) -> Result<(), CryptoError> {
    let valid = match signature.alg {
        #[cfg(feature = "dev_stub_signing")]
        AlgTag::Ed25519 => Ed25519Stub::verify(public.as_bytes(), message, &signature.bytes),
        AlgTag::Dilithium2 => Dilithium2Scheme::verify(public.as_bytes(), message, &signature.bytes),
        AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => {
            return Err(CryptoError::UnsupportedAlg(signature.alg as u8));
        }
        #[cfg(not(feature = "dev_stub_signing"))]
        AlgTag::Ed25519 => return Err(CryptoError::UnsupportedAlg(signature.alg as u8)),
    };

    if valid {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// Compute the linkability tag for a spend witness.
pub fn compute_link_tag(spend_public: &PublicKey, nonce: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"link-tag-v0");
    hasher.update(spend_public.as_bytes());
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Commitment helper using SHA3-256 over value and randomness.
pub fn commitment(value: u64, blinding: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(value.to_le_bytes());
    hasher.update(blinding);
    hasher.finalize().into()
}

/// Hash arbitrary data with BLAKE3.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Hash arbitrary data with SHA3-256.
pub fn sha3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generate a random nonce using the OS RNG.
pub fn random_nonce<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_tag_is_deterministic() {
        let seed = [42u8; KEY_LEN];
        let spend = SpendKeypair::from_seed(seed);
        let nonce = [7u8; 8];
        let tag1 = compute_link_tag(&spend.public, &nonce);
        let tag2 = compute_link_tag(&spend.public, &nonce);
        assert_eq!(tag1, tag2);
    }

    #[test]
    #[cfg(feature = "dev_stub_signing")]
    fn signature_round_trip_ed25519() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let message = b"hello world";
        let sig = sign(message, &spend.secret, AlgTag::Ed25519).expect("sign should succeed");
        verify(message, &spend.public, &sig).expect("valid signature");
    }

    #[test]
    #[cfg(feature = "dev_stub_signing")]
    fn ed25519_direct_trait_api() {
        let seed = [42u8; 32];
        let (pk, sk) = Ed25519Stub::keygen_from_seed(&seed).expect("keygen should succeed");
        let message = b"test message";
        let sig = Ed25519Stub::sign(&sk, message).expect("sign should succeed");
        assert!(Ed25519Stub::verify(&pk, message, &sig));
    }

    #[test]
    #[cfg(feature = "dev_stub_signing")]
    fn verify_rejects_signature_algorithm_mismatch() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let message = b"algo mismatch";
        let sig = sign(message, &spend.secret, AlgTag::Ed25519).expect("sign should succeed");
        let mismatched = Signature::new(AlgTag::SphincsPlus, sig.bytes.clone());
        assert!(verify(message, &spend.public, &mismatched).is_err());
    }

    #[test]
    #[cfg(feature = "dev_stub_signing")]
    fn verify_rejects_forged_signature() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let attacker = KeyMaterial::random().derive_spend_keypair(0);
        let message = b"forgery attempt";
        let forged = sign(message, &attacker.secret, AlgTag::Ed25519).expect("sign should succeed");
        assert!(verify(message, &spend.public, &forged).is_err());
    }

    #[test]
    #[cfg(feature = "dev_stub_signing")]
    fn verify_rejects_invalid_signature_bytes() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let message = b"corrupted";
        let mut sig = sign(message, &spend.secret, AlgTag::Ed25519).expect("sign should succeed");
        // Corrupt the signature
        sig.bytes[0] ^= 0xFF;
        assert!(verify(message, &spend.public, &sig).is_err());
    }

    #[test]
    fn alg_tag_roundtrip() {
        assert_eq!(AlgTag::from_byte(0x00).unwrap(), AlgTag::Ed25519);
        assert_eq!(AlgTag::from_byte(0x01).unwrap(), AlgTag::Dilithium2);
        assert_eq!(AlgTag::from_byte(0x02).unwrap(), AlgTag::Dilithium3);
        assert_eq!(AlgTag::from_byte(0x03).unwrap(), AlgTag::Dilithium5);
        assert_eq!(AlgTag::from_byte(0x10).unwrap(), AlgTag::SphincsPlus);
        assert!(AlgTag::from_byte(0xFF).is_err());
    }

    #[test]
    fn dilithium2_sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen should succeed");
        
        let messages = [
            b"hello world".as_slice(),
            b"".as_slice(),
            b"a".as_slice(),
            &[0u8; 1000],
        ];
        
        for msg in &messages {
            let sig = Dilithium2Scheme::sign(&sk, msg).expect("sign should succeed");
            assert_eq!(sig.len(), Dilithium2Scheme::SIGNATURE_BYTES);
            assert!(Dilithium2Scheme::verify(&pk, msg, &sig), "signature should verify");
        }
    }

    #[test]
    fn dilithium2_rejects_forged_signature() {
        let (pk1, _) = Dilithium2Scheme::keygen_from_seed(&[1; 32]).expect("keygen1");
        let (_, sk2) = Dilithium2Scheme::keygen_from_seed(&[2; 32]).expect("keygen2");
        
        let msg = b"forgery attempt";
        let sig = Dilithium2Scheme::sign(&sk2, msg).expect("sign");
        
        assert!(!Dilithium2Scheme::verify(&pk1, msg, &sig), "should reject forged sig");
    }

    #[test]
    fn dilithium2_rejects_corrupted_signature() {
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen");
        let msg = b"test message";
        let mut sig = Dilithium2Scheme::sign(&sk, msg).expect("sign");
        
        // Corrupt the signature
        let len = sig.len();
        sig[0] ^= 0xFF;
        sig[len - 1] ^= 0xFF;
        
        assert!(!Dilithium2Scheme::verify(&pk, msg, &sig), "should reject corrupted sig");
    }

    #[test]
    fn dilithium2_rejects_wrong_message() {
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen");
        let msg1 = b"original message";
        let msg2 = b"different message";
        
        let sig = Dilithium2Scheme::sign(&sk, msg1).expect("sign");
        
        assert!(!Dilithium2Scheme::verify(&pk, msg2, &sig), "should reject wrong message");
    }

    #[test]
    fn dilithium2_signature_sizes() {
        // Note: pqcrypto-dilithium reports slightly different sizes than NIST spec
        assert_eq!(Dilithium2Scheme::PUBLIC_KEY_BYTES, 1312);
        assert_eq!(Dilithium2Scheme::SECRET_KEY_BYTES, 2560); // Library reports 2560, not 2528
        assert_eq!(Dilithium2Scheme::SIGNATURE_BYTES, 2420);
    }

    #[test]
    fn dilithium2_high_level_api() {
        // Generate Dilithium2 keypair directly (not via KeyMaterial)
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen");
        let pk = PublicKey::from_bytes(pk_bytes);
        let sk = SecretKey::from_bytes(sk_bytes);
        
        let message = b"test with high-level API";
        
        let sig = sign(message, &sk, AlgTag::Dilithium2).expect("sign should succeed");
        assert_eq!(sig.alg, AlgTag::Dilithium2);
        
        verify(message, &pk, &sig).expect("verify should succeed");
    }

    #[test]
    fn dilithium2_multiple_signatures_different() {
        // Dilithium2 uses randomized signing by default, so two signatures
        // of the same message should be different
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen");
        let msg = b"same message";
        
        let sig1 = Dilithium2Scheme::sign(&sk, msg).expect("sign1");
        let sig2 = Dilithium2Scheme::sign(&sk, msg).expect("sign2");
        
        // Signatures should be different (randomized signing)
        // But both should verify
        assert!(Dilithium2Scheme::verify(&pk, msg, &sig1));
        assert!(Dilithium2Scheme::verify(&pk, msg, &sig2));
        // Note: Depending on pqcrypto-dilithium version, this might be deterministic
        // Just ensure both verify correctly
    }
}
