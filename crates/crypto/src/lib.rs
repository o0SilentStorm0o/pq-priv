//! Cryptographic primitives for the PQ-PRIV prototype.
//!
//! The current implementation focuses on providing a consistent API and
//! deterministic key-derivation pipeline that follows the blueprint
//! described in the project specification.  The current signing routine
//! relies on Ed25519 as a stand-in until Dilithium/SPHINCS+ bindings are
//! wired in; the API is designed so that swapping implementations only
//! requires touching this module.

use std::convert::TryInto;

use blake3::derive_key;
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
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
    /// Placeholder Dilithium implementation.
    Dilithium = 0x01,
    /// Placeholder SPHINCS+ implementation.
    SphincsPlus = 0x02,
}

impl AlgTag {
    pub fn from_byte(byte: u8) -> Result<Self, CryptoError> {
        match byte {
            0x01 => Ok(Self::Dilithium),
            0x02 => Ok(Self::SphincsPlus),
            other => Err(CryptoError::UnsupportedAlg(other)),
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
    // Expand the deterministic seed into a signing key using ChaCha20 to
    // avoid trivial low-entropy keys.
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut sk_bytes = [0u8; KEY_LEN];
    rng.fill_bytes(&mut sk_bytes);
    let signing = SigningKey::from_bytes(&sk_bytes);
    let verifying = signing.verifying_key();
    (
        PublicKey::from_bytes(verifying.to_bytes().to_vec()),
        SecretKey::from_bytes(signing.to_bytes().to_vec()),
    )
}

/// Minimal view token shared with auditors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewToken {
    pub tag: [u8; KEY_LEN],
}

/// Ed25519-based placeholder signature scheme.
pub fn sign(message: &[u8], secret: &SecretKey, alg: AlgTag) -> Signature {
    let sk_bytes: [u8; KEY_LEN] = secret
        .as_bytes()
        .try_into()
        .expect("secret key must be 32 bytes");
    let signing = SigningKey::from_bytes(&sk_bytes);
    let sig = signing.sign(message);
    Signature::new(alg, sig.to_bytes().to_vec())
}

/// Verify a signature.
pub fn verify(
    message: &[u8],
    public: &PublicKey,
    signature: &Signature,
) -> Result<(), CryptoError> {
    if signature.alg != AlgTag::Dilithium {
        return Err(CryptoError::UnsupportedAlg(signature.alg as u8));
    }
    let vk_bytes: [u8; 32] = public
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let verifying = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let sig_bytes: [u8; 64] = signature
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig = DalekSignature::from_bytes(&sig_bytes);
    verifying
        .verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
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
    fn signature_round_trip() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let message = b"hello world";
        let sig = sign(message, &spend.secret, AlgTag::Dilithium);
        verify(message, &spend.public, &sig).expect("valid signature");
    }

    #[test]
    fn verify_rejects_signature_algorithm_mismatch() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let message = b"algo mismatch";
        let sig = sign(message, &spend.secret, AlgTag::Dilithium);
        let mismatched = Signature::new(AlgTag::SphincsPlus, sig.bytes.clone());
        assert!(verify(message, &spend.public, &mismatched).is_err());
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let attacker = KeyMaterial::random().derive_spend_keypair(0);
        let message = b"forgery attempt";
        let forged = sign(message, &attacker.secret, AlgTag::Dilithium);
        assert!(verify(message, &spend.public, &forged).is_err());
    }
}
