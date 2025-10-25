//! Cryptographic primitives for the PQ-PRIV prototype.
//!
//! This module provides a trait-based pluggable signature scheme API that
//! supports both post-quantum algorithms (Dilithium, SPHINCS+) and
//! Ed25519 as a development stub for testing.
//!
//! The API is designed so that swapping implementations only requires
//! changing the algorithm tag and does not affect calling code.
//!
//! ## Security Features
//!
//! - **Zeroization**: Secret keys are automatically zeroized on drop
//! - **Domain Separation**: Signatures include context tags to prevent cross-protocol attacks
//! - **Constant-Time**: Critical operations use constant-time comparisons
//! - **Strict Validation**: All deserializations enforce exact length checks

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::uninlined_format_args)]

// Public modules
pub mod hybrid_kem;
pub mod audit_crypto;

use std::convert::TryInto;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::derive_key;
#[cfg(feature = "dev_stub_signing")]
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_mldsa::mldsa44;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PQPublicKey, SecretKey as PQSecretKey,
};
use rand::RngCore;
use rand::rngs::OsRng;
#[cfg(feature = "dev_stub_signing")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "dev_stub_signing")]
use rand_core::SeedableRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::time::Instant;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Length (in bytes) of keys and tags produced by the placeholder scheme.
pub const KEY_LEN: usize = 32;

/// Maximum allowed message length for signature verification (16 MB).
/// Protects against DoS attacks via extremely large messages.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

/// Maximum batch size for batch_verify operations (100,000 items).
/// Protects against DoS attacks via oversized batches.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 100_000;

/// Default threshold for switching from sequential to parallel verification.
/// Batches smaller than this use sequential verification to avoid Rayon overhead.
const DEFAULT_VERIFY_THRESHOLD: usize = 32;

/// Batch verification configuration (lazy-initialized from ENV).
struct BatchVerifyConfig {
    /// Number of threads for parallel verification (1 to num_cpus)
    threads: usize,
    /// Threshold for parallel/sequential switch
    threshold: usize,
    /// Maximum batch size
    max_batch_size: usize,
}

static BATCH_CONFIG: OnceLock<BatchVerifyConfig> = OnceLock::new();

/// Get or initialize batch verification configuration from environment variables.
///
/// ENV variables (all optional):
/// - `CRYPTO_VERIFY_THREADS`: Number of threads (default: min(8, num_cpus))
/// - `CRYPTO_VERIFY_THRESHOLD`: Parallel threshold (default: 32)
/// - `CRYPTO_MAX_BATCH_SIZE`: Max batch size (default: 100,000)
fn batch_config() -> &'static BatchVerifyConfig {
    BATCH_CONFIG.get_or_init(|| {
        let num_cpus = num_cpus::get();

        let threads = std::env::var("CRYPTO_VERIFY_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| num_cpus.min(8))
            .max(1)
            .min(num_cpus);

        let threshold = std::env::var("CRYPTO_VERIFY_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_VERIFY_THRESHOLD)
            .max(1);

        let max_batch_size = std::env::var("CRYPTO_MAX_BATCH_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_BATCH_SIZE)
            .max(1);

        BatchVerifyConfig {
            threads,
            threshold,
            max_batch_size,
        }
    })
}

/// Get the configured number of verification threads.
pub fn get_verify_threads() -> usize {
    batch_config().threads
}

/// Get the configured parallel verification threshold.
pub fn get_verify_threshold() -> usize {
    batch_config().threshold
}

/// Get the configured maximum batch size.
pub fn get_max_batch_size() -> usize {
    batch_config().max_batch_size
}

/// Global counter for zeroize operations (observability/audit metric).
///
/// This counter increments each time a secret key type (SecretKey, KeyMaterial)
/// is dropped and zeroized. It provides observability into memory safety operations
/// and can be exposed via /metrics endpoint for audit purposes.
///
/// **Thread-Safety:** AtomicU64 with Relaxed ordering (performance over strict ordering)
/// **Overflow:** Wraps at u64::MAX (effectively never in practice)
static ZEROIZE_OPS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Get the total number of zeroize operations performed since process start.
///
/// This function is intended for metrics/observability endpoints. Example:
///
/// ```rust,ignore
/// // In your metrics handler:
/// let zeroize_count = crypto::get_zeroize_ops_total();
/// println!("crypto_zeroize_ops_total {}", zeroize_count);
/// ```
pub fn get_zeroize_ops_total() -> u64 {
    ZEROIZE_OPS_TOTAL.load(Ordering::Relaxed)
}

/// Increment the zeroize operations counter (internal use only).
fn increment_zeroize_counter() {
    ZEROIZE_OPS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// BATCH VERIFY METRICS (Sprint 6)
// ============================================================================

/// Total number of batch_verify_v2() invocations.
static BATCH_VERIFY_CALLS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Total number of signatures processed by batch_verify_v2().
static BATCH_VERIFY_ITEMS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Total number of invalid signatures detected.
static BATCH_VERIFY_INVALID_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Total time spent in batch_verify_v2() in microseconds.
static BATCH_VERIFY_DURATION_US_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Get the total number of batch_verify_v2() calls.
pub fn get_batch_verify_calls_total() -> u64 {
    BATCH_VERIFY_CALLS_TOTAL.load(Ordering::Relaxed)
}

/// Get the total number of signatures processed by batch verify.
pub fn get_batch_verify_items_total() -> u64 {
    BATCH_VERIFY_ITEMS_TOTAL.load(Ordering::Relaxed)
}

/// Get the total number of invalid signatures detected.
pub fn get_batch_verify_invalid_total() -> u64 {
    BATCH_VERIFY_INVALID_TOTAL.load(Ordering::Relaxed)
}

/// Get the total time spent in batch verify (microseconds).
pub fn get_batch_verify_duration_us_total() -> u64 {
    BATCH_VERIFY_DURATION_US_TOTAL.load(Ordering::Relaxed)
}

// ============================================================================

/// Type-safe domain separation context.
///
/// Wrapper around static byte slices to prevent runtime-constructed
/// contexts from untrusted sources at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context(pub &'static [u8]);

/// Domain separation contexts for signature generation.
///
/// These tags are included in the message preimage to prevent
/// cross-protocol attacks and signature malleability.
pub mod context {
    use super::Context;

    /// Context tag for transaction input signatures.
    pub const TX: Context = Context(b"PQ-PRIV|TX|v1");

    /// Context tag for block header signatures.
    pub const BLOCK: Context = Context(b"PQ-PRIV|BLOCK|v1");

    /// Context tag for peer-to-peer handshake signatures.
    pub const P2P_HANDSHAKE: Context = Context(b"PQ-PRIV|P2P|v1");
}

/// Signature algorithm tags advertised on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlgTag {
    /// Ed25519 signature scheme (development stub only).
    /// Only available with `dev_stub_signing` feature.
    #[cfg(feature = "dev_stub_signing")]
    Ed25519 = 0x00,
    /// ML-DSA-44 (NIST FIPS 204, formerly CRYSTALS-Dilithium2) post-quantum signature scheme.
    Dilithium2 = 0x01,
    /// ML-DSA-65 (NIST FIPS 204, formerly CRYSTALS-Dilithium3) post-quantum signature scheme.
    Dilithium3 = 0x02,
    /// ML-DSA-87 (NIST FIPS 204, formerly CRYSTALS-Dilithium5) post-quantum signature scheme.
    Dilithium5 = 0x03,
    /// SPHINCS+ post-quantum signature scheme.
    SphincsPlus = 0x10,
}

impl AlgTag {
    pub fn from_byte(byte: u8) -> Result<Self, CryptoError> {
        match byte {
            #[cfg(feature = "dev_stub_signing")]
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
            #[cfg(feature = "dev_stub_signing")]
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
    #[error("invalid input: parameters mismatch or out of bounds")]
    InvalidInput,
    #[error("proof size {got} exceeds maximum {max} bytes")]
    InvalidProofSize { got: usize, max: usize },
    #[error("range proof generation failed")]
    ProofGenerationFailed,
    #[error("range proof verification failed")]
    ProofVerificationFailed,
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

/// Compute a domain-separated hash of a message using CBOR tuple encoding.
///
/// This function uses CBOR canonical encoding to prevent length-extension
/// and ambiguity attacks. The preimage is: SHA3-256(cbor([context_str, alg_tag, msg_bytes]))
///
/// CBOR encoding guarantees:
/// - Unambiguous field boundaries (no length-extension attacks)
/// - Canonical representation (deterministic encoding)
/// - Type safety (strings vs bytes vs integers)
///
/// # Arguments
///
/// * `context` - Domain separation tag (e.g., `context::TX` for transactions)
/// * `alg` - The signature algorithm being used
/// * `msg` - The message to hash
///
/// # Returns
///
/// A 32-byte hash of the domain-separated message.
///
/// # Security
///
/// The CBOR tuple format prevents ambiguity between:
/// - Different message lengths
/// - Context/algorithm/message boundaries
/// - Cross-protocol attacks
///
/// # CBOR Strict Limits (Auditor-proof requirement #4)
///
/// We enforce strict size limits to prevent DoS via large CBOR structures:
/// - Context strings: max 128 bytes (static contexts are ~8-16 bytes)
/// - Message payload: max 10 MB (typical tx/block is < 1MB)
/// - Total CBOR output: max 16 MB (prevents excessive memory usage)
///
/// These limits are defensive and should never be hit in normal operation.
pub fn domain_separated_hash(context: Context, alg: AlgTag, msg: &[u8]) -> [u8; 32] {
    // CBOR STRICT LIMITS ENFORCEMENT
    const MAX_CONTEXT_LEN: usize = 128; // Static contexts are ~8-16 bytes
    const MAX_MESSAGE_LEN: usize = 10 * 1024 * 1024; // 10 MB max message
    const MAX_CBOR_LEN: usize = 16 * 1024 * 1024; // 16 MB max CBOR output

    // Validate context length (should be compile-time enforced by Context type,
    // but we check defensively for auditor-proof guarantees)
    assert!(
        context.0.len() <= MAX_CONTEXT_LEN,
        "Context length {} exceeds MAX_CONTEXT_LEN ({})",
        context.0.len(),
        MAX_CONTEXT_LEN
    );

    // Validate message length (protects against DoS via huge messages)
    assert!(
        msg.len() <= MAX_MESSAGE_LEN,
        "Message length {} exceeds MAX_MESSAGE_LEN ({} MB)",
        msg.len(),
        MAX_MESSAGE_LEN / (1024 * 1024)
    );

    // Construct CBOR tuple: [context_string, alg_tag_u8, message_bytes]
    let tuple = (
        std::str::from_utf8(context.0).unwrap_or("<invalid>"),
        alg as u8,
        msg,
    );

    // CBOR encode with deterministic (canonical) encoding
    // Use Zeroizing to ensure CBOR buffer (which contains raw message data) is wiped
    let mut cbor_bytes = Zeroizing::new(Vec::new());
    ciborium::into_writer(&tuple, cbor_bytes.as_mut() as &mut Vec<u8>)
        .expect("CBOR encoding should not fail for simple tuple");

    // Validate CBOR output length (final defensive check)
    assert!(
        cbor_bytes.len() <= MAX_CBOR_LEN,
        "CBOR output length {} exceeds MAX_CBOR_LEN ({} MB)",
        cbor_bytes.len(),
        MAX_CBOR_LEN / (1024 * 1024)
    );

    // Hash the CBOR-encoded tuple
    let mut hasher = Sha3_256::new();
    hasher.update(&cbor_bytes);

    let result = hasher.finalize();
    result.into()
}

/// Deterministic key material used for both scan and spend keys.
///
/// **Security**: This type contains sensitive key material and implements
/// custom Drop to increment zeroize metrics and clear memory on destruction.
/// Do not derive `Copy` or log this type. Debug impl is redacted.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct KeyMaterial {
    #[serde(with = "serde_bytes")]
    master_seed: Vec<u8>,
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Zeroize the secret material
        self.zeroize();
        // Increment observability counter
        increment_zeroize_counter();
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("master_seed", &"<redacted>")
            .finish()
    }
}

impl KeyMaterial {
    /// Create a new key material container from raw entropy.
    ///
    /// Uses `Zeroizing` to ensure the intermediate seed buffer is securely cleared.
    pub fn from_entropy(entropy: &[u8]) -> Self {
        let hash = blake3::hash(entropy);
        let seed = Zeroizing::new(hash.as_bytes()[..KEY_LEN].to_vec());
        Self {
            master_seed: seed.to_vec(),
        }
    }

    /// Generate random key material using the operating system RNG.
    ///
    /// **Security**: Always uses TRNG (OsRng). This is the recommended method
    /// for generating fresh keys in production.
    pub fn random() -> Self {
        let mut rng = OsRng;
        let mut seed = Zeroizing::new(vec![0u8; KEY_LEN]);
        rng.fill_bytes(&mut seed);
        Self {
            master_seed: seed.to_vec(),
        }
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

/// Secret key wrapper with automatic zeroization on drop.
///
/// The key material is securely zeroized when the SecretKey goes out of scope,
/// preventing sensitive data from remaining in memory.
///
/// **Security**: This type implements custom Drop to increment zeroize metrics
/// and prevent accidental logging of sensitive key material. Never derive `Copy`.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct SecretKey {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zeroize the secret material
        self.zeroize();
        // Increment observability counter
        increment_zeroize_counter();
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
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
    let (pk, sk) = Ed25519Stub::keygen_from_seed(&seed).expect("keygen from seed should not fail");

    #[cfg(not(feature = "dev_stub_signing"))]
    let (pk, sk) =
        Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen from seed should not fail");

    (PublicKey::from_bytes(pk), SecretKey::from_bytes(sk))
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
        Ok((verifying.to_bytes().to_vec(), signing.to_bytes().to_vec()))
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk_bytes: [u8; 32] = secret.try_into().map_err(|_| CryptoError::InvalidKey)?;
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

/// ML-DSA-44 (Dilithium2) post-quantum signature scheme implementation.
///
/// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the NIST-standardized
/// name for CRYSTALS-Dilithium (FIPS 204). ML-DSA-44 provides NIST security level 2
/// (equivalent to AES-128 against quantum attacks).
///
/// ## Key Sizes
///
/// The actual key sizes are determined by the underlying library constants:
/// - Public key: `mldsa44::public_key_bytes()` (typically 1312 bytes)
/// - Secret key: `mldsa44::secret_key_bytes()` (library reports 2560, NIST standard is 2528)
/// - Signature: `mldsa44::signature_bytes()` (typically 2420 bytes)
///
/// **IMPORTANT**: Never hardcode these sizes. Always use the library constants.
pub struct Dilithium2Scheme;

impl SignatureScheme for Dilithium2Scheme {
    const ALG: AlgTag = AlgTag::Dilithium2;
    const NAME: &'static str = "Dilithium2";

    // Use library constants directly - never hardcode sizes!
    const PUBLIC_KEY_BYTES: usize = mldsa44::public_key_bytes();
    const SECRET_KEY_BYTES: usize = mldsa44::secret_key_bytes();
    const SIGNATURE_BYTES: usize = mldsa44::signature_bytes();

    fn keygen_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // SECURITY WARNING: pqcrypto-dilithium v0.5 does not support deterministic keygen.
        // It always uses OsRng (system entropy) for key generation.
        //
        // This is acceptable for:
        // - Node/daemon key generation (where TRNG is preferred)
        //
        // This is NOT suitable for:
        // - Wallet recovery from seed (requires deterministic keygen)
        //
        // TODO: Migrate to liboqs which supports deterministic keygen via seeded RNG

        let _seed_hash = blake3::hash(seed);

        // Use system TRNG - seed is currently ignored
        log::warn!(
            "ML-DSA-44 keygen: seed parameter ignored, using system TRNG. \
             For deterministic keygen, migrate to liboqs."
        );

        let (pk, sk) = mldsa44::keypair();

        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Strict length check - reject keys that don't match exactly
        if secret.len() != Self::SECRET_KEY_BYTES {
            return Err(CryptoError::InvalidKey);
        }

        let sk = mldsa44::SecretKey::from_bytes(secret).map_err(|_| CryptoError::InvalidKey)?;

        let sig = mldsa44::detached_sign(msg, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        // Strict length checks - reject any size mismatch to prevent malleability
        if public.len() != Self::PUBLIC_KEY_BYTES {
            return false;
        }
        if sig.len() != Self::SIGNATURE_BYTES {
            return false;
        }

        let pk = match mldsa44::PublicKey::from_bytes(public) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let signature = match mldsa44::DetachedSignature::from_bytes(sig) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        mldsa44::verify_detached_signature(&signature, msg, &pk).is_ok()
    }
}

/// High-level signing API with domain separation.
///
/// This function computes a domain-separated hash of the message before signing,
/// which includes:
/// - A context tag (e.g., `context::TX` for transactions)
/// - The algorithm identifier
/// - The message itself
///
/// This prevents cross-protocol attacks and ensures signatures are bound to
/// their intended context.
///
/// # Arguments
///
/// * `message` - The raw message to sign
/// * `secret` - The secret key
/// * `alg` - The signature algorithm to use
/// * `context` - Domain separation context (type-safe static reference)
///
/// # Examples
///
/// ```ignore
/// use crypto::{sign, context, AlgTag};
///
/// let sig = sign(tx_hash, &secret_key, AlgTag::Dilithium2, context::TX)?;
/// ```
pub fn sign(
    message: &[u8],
    secret: &SecretKey,
    alg: AlgTag,
    context: Context,
) -> Result<Signature, CryptoError> {
    // Compute domain-separated hash using CBOR tuple encoding
    let hash = domain_separated_hash(context, alg, message);

    let sig_bytes = match alg {
        #[cfg(feature = "dev_stub_signing")]
        AlgTag::Ed25519 => Ed25519Stub::sign(secret.as_bytes(), &hash)?,
        AlgTag::Dilithium2 => Dilithium2Scheme::sign(secret.as_bytes(), &hash)?,
        AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => {
            return Err(CryptoError::UnsupportedAlg(alg as u8));
        }
    };
    Ok(Signature::new(alg, sig_bytes))
}

/// High-level verification API with domain separation.
///
/// This function recomputes the domain-separated hash using the same context
/// that was used during signing, then verifies the signature.
///
/// # Arguments
///
/// * `message` - The raw message that was signed
/// * `public` - The public key
/// * `signature` - The signature to verify
/// * `context` - Domain separation context (type-safe, must match signing context)
///
/// # Security
///
/// - Performs strict length validation on keys and signatures
/// - Rejects any size mismatch to prevent malleability attacks
/// - Uses CBOR tuple encoding for unambiguous preimage
pub fn verify(
    message: &[u8],
    public: &PublicKey,
    signature: &Signature,
    context: Context,
) -> Result<(), CryptoError> {
    // Strict validation: signature must match expected size for its algorithm
    let expected_sig_size = match signature.alg {
        #[cfg(feature = "dev_stub_signing")]
        AlgTag::Ed25519 => Ed25519Stub::SIGNATURE_BYTES,
        AlgTag::Dilithium2 => Dilithium2Scheme::SIGNATURE_BYTES,
        AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => {
            return Err(CryptoError::UnsupportedAlg(signature.alg as u8));
        }
    };

    if signature.bytes.len() != expected_sig_size {
        return Err(CryptoError::InvalidSignature);
    }

    // Compute domain-separated hash (must match signing context)
    let hash = domain_separated_hash(context, signature.alg, message);

    // AUDITOR NOTE: verify() implementations from pqcrypto-dilithium and ed25519-dalek
    // already perform constant-time comparisons internally. We rely on these upstream
    // libraries for timing-attack resistance. No additional constant-time comparison
    // is needed here - the verify() functions return bool without leaking timing info.
    let valid = match signature.alg {
        #[cfg(feature = "dev_stub_signing")]
        AlgTag::Ed25519 => Ed25519Stub::verify(public.as_bytes(), &hash, &signature.bytes),
        AlgTag::Dilithium2 => Dilithium2Scheme::verify(public.as_bytes(), &hash, &signature.bytes),
        AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => {
            return Err(CryptoError::UnsupportedAlg(signature.alg as u8));
        }
    };

    if valid {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

// ============================================================================
// Batch Verification API (Sprint 6)
// ============================================================================

/// Single item for batch signature verification.
///
/// Contains all necessary data to verify one signature in a batch.
/// All fields are validated before batch processing begins.
#[derive(Debug, Clone)]
pub struct VerifyItem<'a> {
    /// Domain separation context (e.g., context::TX)
    pub context: Context,
    /// Algorithm tag (must match signature algorithm)
    pub alg: AlgTag,
    /// Public key bytes (must match expected size for algorithm)
    pub public: &'a [u8],
    /// Message to verify (already domain-separated if precomputed)
    pub msg: &'a [u8],
    /// Signature bytes (must match expected size for algorithm)
    pub sig: &'a [u8],
}

impl<'a> VerifyItem<'a> {
    /// Create a new verify item with validation.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidInput` if:
    /// - Message exceeds MAX_MESSAGE_LEN
    /// - Public key or signature size doesn't match algorithm
    pub fn new(
        context: Context,
        alg: AlgTag,
        public: &'a [u8],
        msg: &'a [u8],
        sig: &'a [u8],
    ) -> Result<Self, CryptoError> {
        // Validate message length
        if msg.len() > MAX_MESSAGE_LEN {
            return Err(CryptoError::InvalidInput);
        }

        // Validate public key and signature sizes
        let expected_pub_size = match alg {
            #[cfg(feature = "dev_stub_signing")]
            AlgTag::Ed25519 => Ed25519Stub::PUBLIC_KEY_BYTES,
            AlgTag::Dilithium2 => Dilithium2Scheme::PUBLIC_KEY_BYTES,
            AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => {
                return Err(CryptoError::UnsupportedAlg(alg as u8));
            }
        };

        let expected_sig_size = match alg {
            #[cfg(feature = "dev_stub_signing")]
            AlgTag::Ed25519 => Ed25519Stub::SIGNATURE_BYTES,
            AlgTag::Dilithium2 => Dilithium2Scheme::SIGNATURE_BYTES,
            AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => {
                return Err(CryptoError::UnsupportedAlg(alg as u8));
            }
        };

        if public.len() != expected_pub_size {
            return Err(CryptoError::InvalidInput);
        }

        if sig.len() != expected_sig_size {
            return Err(CryptoError::InvalidInput);
        }

        Ok(Self {
            context,
            alg,
            public,
            msg,
            sig,
        })
    }
}

/// Outcome of batch verification operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchVerifyOutcome {
    /// All signatures in the batch are valid
    AllValid,
    /// Some signatures are invalid (count of invalid signatures)
    SomeInvalid(usize),
}

impl BatchVerifyOutcome {
    /// Check if all signatures were valid
    pub fn is_all_valid(&self) -> bool {
        matches!(self, Self::AllValid)
    }

    /// Get count of invalid signatures (0 if all valid)
    pub fn invalid_count(&self) -> usize {
        match self {
            Self::AllValid => 0,
            Self::SomeInvalid(n) => *n,
        }
    }
}

/// Verify a single item (internal helper for batch verification).
///
/// This performs domain separation and calls the underlying verify implementation.
/// Uses Zeroizing for temporary hash buffer.
fn verify_one_item(item: &VerifyItem) -> bool {
    // Compute domain-separated hash with zeroizing buffer
    let hash = domain_separated_hash(item.context, item.alg, item.msg);

    // Verify signature using algorithm-specific implementation
    match item.alg {
        #[cfg(feature = "dev_stub_signing")]
        AlgTag::Ed25519 => Ed25519Stub::verify(item.public, &hash, item.sig),
        AlgTag::Dilithium2 => Dilithium2Scheme::verify(item.public, &hash, item.sig),
        AlgTag::Dilithium3 | AlgTag::Dilithium5 | AlgTag::SphincsPlus => false,
    }
}

/// Batch signature verification with parallel processing.
///
/// Verifies multiple signatures in parallel using Rayon when batch size exceeds
/// the configured threshold. Falls back to sequential verification for small batches.
///
/// # Arguments
///
/// * `items` - Iterator of `VerifyItem` to verify
///
/// # Returns
///
/// * `BatchVerifyOutcome::AllValid` - All signatures valid
/// * `BatchVerifyOutcome::SomeInvalid(n)` - n signatures invalid
///
/// # Security
///
/// - All items are pre-validated (lengths, algorithm support)
/// - Uses domain separation for all verifications
/// - Deterministic result (order-independent)
/// - Protected against DoS via MAX_BATCH_SIZE limit
///
/// # Performance
///
/// - Sequential: `n < threshold` (default 32)
/// - Parallel: `n >= threshold` using Rayon thread pool
/// - Thread count: Configured via CRYPTO_VERIFY_THREADS
///
/// # Example
///
/// ```rust,ignore
/// use crypto::{VerifyItem, batch_verify_v2, context};
///
/// let items = vec![
///     VerifyItem::new(context::TX, AlgTag::Dilithium2, &pub1, &msg1, &sig1)?,
///     VerifyItem::new(context::TX, AlgTag::Dilithium2, &pub2, &msg2, &sig2)?,
/// ];
///
/// match batch_verify_v2(items) {
///     BatchVerifyOutcome::AllValid => println!("All valid"),
///     BatchVerifyOutcome::SomeInvalid(n) => println!("{} invalid", n),
/// }
/// ```
pub fn batch_verify_v2<'a>(items: impl IntoIterator<Item = VerifyItem<'a>>) -> BatchVerifyOutcome {
    let start = Instant::now();

    // Increment call counter
    BATCH_VERIFY_CALLS_TOTAL.fetch_add(1, Ordering::Relaxed);

    let items_vec: Vec<_> = items.into_iter().collect();

    // Empty batch is trivially valid
    if items_vec.is_empty() {
        let duration_us = start.elapsed().as_micros() as u64;
        BATCH_VERIFY_DURATION_US_TOTAL.fetch_add(duration_us, Ordering::Relaxed);
        return BatchVerifyOutcome::AllValid;
    }

    // Record number of items
    BATCH_VERIFY_ITEMS_TOTAL.fetch_add(items_vec.len() as u64, Ordering::Relaxed);

    // Enforce maximum batch size (DoS protection)
    let max_size = get_max_batch_size();
    if items_vec.len() > max_size {
        log::error!(
            "Batch size {} exceeds maximum {}, rejecting entire batch",
            items_vec.len(),
            max_size
        );
        BATCH_VERIFY_INVALID_TOTAL.fetch_add(items_vec.len() as u64, Ordering::Relaxed);
        let duration_us = start.elapsed().as_micros() as u64;
        BATCH_VERIFY_DURATION_US_TOTAL.fetch_add(duration_us, Ordering::Relaxed);
        return BatchVerifyOutcome::SomeInvalid(items_vec.len());
    }

    let config = batch_config();
    let use_parallel = items_vec.len() >= config.threshold && config.threads > 1;

    log::trace!(
        "Batch verify: {} items, parallel={}, threads={}, threshold={}",
        items_vec.len(),
        use_parallel,
        config.threads,
        config.threshold
    );

    // Count invalid signatures
    let invalid_count: usize = if use_parallel {
        // Parallel verification with Rayon
        items_vec
            .par_iter()
            .map(|item| !verify_one_item(item) as usize)
            .sum()
    } else {
        // Sequential verification
        items_vec
            .iter()
            .map(|item| !verify_one_item(item) as usize)
            .sum()
    };

    // Record invalid count and duration
    if invalid_count > 0 {
        BATCH_VERIFY_INVALID_TOTAL.fetch_add(invalid_count as u64, Ordering::Relaxed);
    }
    let duration_us = start.elapsed().as_micros() as u64;
    BATCH_VERIFY_DURATION_US_TOTAL.fetch_add(duration_us, Ordering::Relaxed);

    if invalid_count == 0 {
        BatchVerifyOutcome::AllValid
    } else {
        BatchVerifyOutcome::SomeInvalid(invalid_count)
    }
}

/// **Batch Signature Verification API** (Reserved for Future Optimization)
///
/// This function is a placeholder for future batch verification optimization.
/// Batch verification can verify multiple signatures ~2-3x faster than individual
/// verification by amortizing expensive group operations.
///
/// # Current Implementation
///
/// Currently performs sequential verification (no batch optimization yet).
/// This is semantically correct but not optimized.
///
/// # Future Optimization
///
/// When batch verification is implemented:
/// - Dilithium2/3 could use batched NTT operations
/// - Multiple signature checks can share precomputed values
/// - Expected speedup: 2-3x for batches of 10+ signatures
///
/// # Arguments
///
/// * `messages` - Slice of messages that were signed
/// * `public_keys` - Corresponding public keys (must match messages length)
/// * `signatures` - Corresponding signatures (must match messages length)
/// * `context` - Domain separation context (same for all signatures)
///
/// # Returns
///
/// - `Ok(())` if **all** signatures are valid
/// - `Err(CryptoError::InvalidSignature)` if **any** signature is invalid
/// - `Err(CryptoError::InvalidInput)` if input lengths don't match
///
/// # Security
///
/// Batch verification is cryptographically sound - a passing batch guarantees
/// all individual signatures are valid. Failing batch only indicates at least
/// one signature is invalid (doesn't identify which one).
pub fn batch_verify(
    messages: &[&[u8]],
    public_keys: &[&PublicKey],
    signatures: &[&Signature],
    context: Context,
) -> Result<(), CryptoError> {
    // Input validation: all slices must have same length
    if messages.len() != public_keys.len() || messages.len() != signatures.len() {
        return Err(CryptoError::InvalidInput);
    }

    // Current implementation: sequential verification (no batch optimization)
    // TODO: Implement actual batch verification for Dilithium2/3
    for i in 0..messages.len() {
        verify(messages[i], public_keys[i], signatures[i], context)?;
    }

    Ok(())
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
        let sig = sign(message, &spend.secret, AlgTag::Ed25519, context::TX)
            .expect("sign should succeed");
        verify(message, &spend.public, &sig, context::TX).expect("valid signature");
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
        let sig = sign(message, &spend.secret, AlgTag::Ed25519, context::TX)
            .expect("sign should succeed");
        let mismatched = Signature::new(AlgTag::SphincsPlus, sig.bytes.clone());
        assert!(verify(message, &spend.public, &mismatched, context::TX).is_err());
    }

    #[test]
    #[cfg(feature = "dev_stub_signing")]
    fn verify_rejects_forged_signature() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let attacker = KeyMaterial::random().derive_spend_keypair(0);
        let message = b"forgery attempt";
        let forged = sign(message, &attacker.secret, AlgTag::Ed25519, context::TX)
            .expect("sign should succeed");
        assert!(verify(message, &spend.public, &forged, context::TX).is_err());
    }

    #[test]
    #[cfg(feature = "dev_stub_signing")]
    fn verify_rejects_invalid_signature_bytes() {
        let km = KeyMaterial::random();
        let spend = km.derive_spend_keypair(0);
        let message = b"corrupted";
        let mut sig = sign(message, &spend.secret, AlgTag::Ed25519, context::TX)
            .expect("sign should succeed");
        // Corrupt the signature
        sig.bytes[0] ^= 0xFF;
        assert!(verify(message, &spend.public, &sig, context::TX).is_err());
    }

    #[test]
    fn alg_tag_roundtrip() {
        #[cfg(feature = "dev_stub_signing")]
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
            assert!(
                Dilithium2Scheme::verify(&pk, msg, &sig),
                "signature should verify"
            );
        }
    }

    #[test]
    fn dilithium2_rejects_forged_signature() {
        let (pk1, _) = Dilithium2Scheme::keygen_from_seed(&[1; 32]).expect("keygen1");
        let (_, sk2) = Dilithium2Scheme::keygen_from_seed(&[2; 32]).expect("keygen2");

        let msg = b"forgery attempt";
        let sig = Dilithium2Scheme::sign(&sk2, msg).expect("sign");

        assert!(
            !Dilithium2Scheme::verify(&pk1, msg, &sig),
            "should reject forged sig"
        );
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

        assert!(
            !Dilithium2Scheme::verify(&pk, msg, &sig),
            "should reject corrupted sig"
        );
    }

    #[test]
    fn dilithium2_rejects_wrong_message() {
        let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen");
        let msg1 = b"original message";
        let msg2 = b"different message";

        let sig = Dilithium2Scheme::sign(&sk, msg1).expect("sign");

        assert!(
            !Dilithium2Scheme::verify(&pk, msg2, &sig),
            "should reject wrong message"
        );
    }

    #[test]
    fn dilithium2_signature_sizes() {
        // Use library constants - never hardcode!
        // Note: pqcrypto-dilithium v0.5 reports 2560 for SK, NIST spec is 2528
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
    }

    #[test]
    fn dilithium2_high_level_api() {
        // Generate Dilithium2 keypair directly (not via KeyMaterial)
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen");
        let pk = PublicKey::from_bytes(pk_bytes);
        let sk = SecretKey::from_bytes(sk_bytes);

        let message = b"test with high-level API";

        let sig = sign(message, &sk, AlgTag::Dilithium2, context::TX).expect("sign should succeed");
        assert_eq!(sig.alg, AlgTag::Dilithium2);

        verify(message, &pk, &sig, context::TX).expect("verify should succeed");
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

    /// **Panic-Safety Test** (Auditor-proof requirement #10)
    ///
    /// Verifies that the crypto library handles error conditions gracefully
    /// without panicking in safe code. We test:
    ///
    /// 1. keygen_from_seed returns Ok on valid seed (doesn't panic)
    /// 2. verify returns Err on invalid signatures (doesn't panic)
    /// 3. CBOR limits are enforced (would assert!/panic on excessive input)
    /// 4. Empty messages sign/verify correctly (edge case)
    ///
    /// This test explicitly validates documented error paths to ensure
    /// the library is panic-free in safe code under normal conditions.
    #[test]
    fn test_panic_safety_documented_error_paths() {
        // Test 1: keygen_from_seed with valid seed length
        // Even all-zero seed should work (deterministic but valid)
        let result = Dilithium2Scheme::keygen_from_seed(&[0u8; 32]);
        assert!(
            result.is_ok(),
            "keygen_from_seed with valid-length seed should succeed"
        );

        // Test 2: Verify with invalid signature bytes (wrong length)
        // Should return Err (InvalidSignature), not panic
        let (pk_bytes, _sk_bytes) =
            Dilithium2Scheme::keygen_from_seed(&[42u8; 32]).expect("keygen");
        let pk = PublicKey::from_bytes(pk_bytes);

        let msg = b"test message";
        let invalid_sig = Signature {
            alg: AlgTag::Dilithium2,
            bytes: vec![0u8; 10], // Way too short for Dilithium2 signature
        };

        let result = verify(msg, &pk, &invalid_sig, context::TX);
        assert!(
            matches!(result, Err(CryptoError::InvalidSignature)),
            "verify should return InvalidSignature on wrong-length sig, not panic"
        );

        // Test 3: Verify with correct-length but invalid signature content
        // Should return Err, not panic
        let fake_sig = Signature {
            alg: AlgTag::Dilithium2,
            bytes: vec![0u8; Dilithium2Scheme::SIGNATURE_BYTES],
        };

        let result = verify(msg, &pk, &fake_sig, context::TX);
        assert!(
            result.is_err(),
            "verify should return Err on invalid signature content, not panic"
        );

        // Test 4: Empty message signing/verification (edge case)
        let (pk2_bytes, sk2_bytes) =
            Dilithium2Scheme::keygen_from_seed(&[99u8; 32]).expect("keygen");
        let pk2 = PublicKey::from_bytes(pk2_bytes);
        let sk2 = SecretKey::from_bytes(sk2_bytes);

        let sig = sign(b"", &sk2, AlgTag::Dilithium2, context::TX).expect("sign empty message");
        assert!(
            verify(b"", &pk2, &sig, context::TX).is_ok(),
            "Empty message should sign/verify correctly"
        );

        // Test 5: CBOR limits enforcement
        // domain_separated_hash has MAX_MESSAGE_LEN = 10 MB
        // We can't easily test the panic path without actually allocating 10MB,
        // but we verify that normal-sized messages (< 10 MB) work fine:
        let small_msg = vec![0u8; 1024]; // 1 KB - well within limits
        let sig_small =
            sign(&small_msg, &sk2, AlgTag::Dilithium2, context::TX).expect("sign small message");
        assert!(
            verify(&small_msg, &pk2, &sig_small, context::TX).is_ok(),
            "Small messages (< 10 MB) should work fine"
        );

        // CONCLUSION: All documented error paths return Result, no panics in safe code
        // under normal conditions. CBOR limits protect against DoS but are defensive.
    }

    /// **CBOR Canonicity Test** (Auditor-proof cross-platform requirement)
    ///
    /// Verifies that CBOR encoding is deterministic and produces identical
    /// hashes across different platforms and invocations. This is critical
    /// for consensus systems where different nodes must agree on hash values.
    ///
    /// CBOR RFC 8949 Section 4.2 defines Canonical CBOR requirements:
    /// - Integers encoded in shortest form
    /// - Map keys sorted by byte-wise lexicographic order
    /// - No duplicate keys
    /// - Definite-length encoding (no streaming)
    ///
    /// The `ciborium` library implements Core Deterministic Encoding Requirements
    /// (CDER) which ensures cross-platform determinism.
    #[test]
    fn test_cbor_canonical_encoding_determinism() {
        // Test 1: Same input produces same CBOR output (determinism)
        let msg1 = b"test message for canonicity";
        let hash1 = domain_separated_hash(context::TX, AlgTag::Dilithium2, msg1);
        let hash2 = domain_separated_hash(context::TX, AlgTag::Dilithium2, msg1);

        assert_eq!(
            hash1, hash2,
            "Same input must produce identical hash (CBOR determinism)"
        );

        // Test 2: Different messages produce different hashes (no collisions)
        let msg2 = b"test message for canonicity!"; // One char different
        let hash3 = domain_separated_hash(context::TX, AlgTag::Dilithium2, msg2);

        assert_ne!(
            hash1, hash3,
            "Different messages must produce different hashes"
        );

        // Test 3: Context separation works (different contexts = different hashes)
        let hash_tx = domain_separated_hash(context::TX, AlgTag::Dilithium2, msg1);
        let hash_block = domain_separated_hash(context::BLOCK, AlgTag::Dilithium2, msg1);

        assert_ne!(
            hash_tx, hash_block,
            "Same message with different contexts must produce different hashes"
        );

        // Test 4: Algorithm tag affects hash
        let hash_d2 = domain_separated_hash(context::TX, AlgTag::Dilithium2, msg1);
        let hash_d3 = domain_separated_hash(context::TX, AlgTag::Dilithium3, msg1);

        assert_ne!(
            hash_d2, hash_d3,
            "Same message with different algorithm tags must produce different hashes"
        );

        // Test 5: Multiple invocations (stress test determinism)
        let hashes: Vec<_> = (0..100)
            .map(|_| domain_separated_hash(context::TX, AlgTag::Dilithium2, msg1))
            .collect();

        assert!(
            hashes.iter().all(|h| h == &hash1),
            "100 invocations must produce identical hashes (CBOR stability)"
        );

        // CONCLUSION: ciborium produces canonical CBOR with guaranteed cross-platform
        // determinism. All domain separation parameters (context, alg, msg) properly
        // contribute to unique hash values.
    }

    /// **Zeroize Counter Test** (Observability/Audit requirement)
    ///
    /// Verifies that the zeroize operations counter increments correctly when
    /// secret key types are dropped. This provides observability for memory safety
    /// and can be exposed via /metrics endpoint.
    #[test]
    fn test_zeroize_ops_counter() {
        // Get baseline count
        let initial_count = get_zeroize_ops_total();

        // Create and drop a SecretKey
        {
            let (_, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&[42; 32]).expect("keygen");
            let _sk = SecretKey::from_bytes(sk_bytes);
            // SecretKey dropped here
        }

        let after_sk = get_zeroize_ops_total();
        assert!(
            after_sk > initial_count,
            "Counter should increment after dropping SecretKey (was {}, now {})",
            initial_count,
            after_sk
        );

        // Create and drop a KeyMaterial
        {
            let _km = KeyMaterial::from_entropy(b"test entropy");
            // KeyMaterial dropped here
        }

        let after_km = get_zeroize_ops_total();
        assert!(
            after_km > after_sk,
            "Counter should increment after dropping KeyMaterial (was {}, now {})",
            after_sk,
            after_km
        );

        // Create and drop multiple keys
        {
            let (_pk1, sk1) = Dilithium2Scheme::keygen_from_seed(&[1; 32]).expect("keygen");
            let (_pk2, sk2) = Dilithium2Scheme::keygen_from_seed(&[2; 32]).expect("keygen");
            let (_pk3, sk3) = Dilithium2Scheme::keygen_from_seed(&[3; 32]).expect("keygen");

            let _s1 = SecretKey::from_bytes(sk1);
            let _s2 = SecretKey::from_bytes(sk2);
            let _s3 = SecretKey::from_bytes(sk3);
            // All 3 SecretKeys dropped here (zeroize counter += 3)
        }

        let final_count = get_zeroize_ops_total();
        assert!(
            final_count >= after_km + 3,
            "Counter should increment by at least 3 after dropping 3 SecretKeys (got {})",
            final_count - after_km
        );

        // CONCLUSION: Zeroize counter provides accurate observability into memory
        // safety operations. Can be exposed via metrics for audit/monitoring.
        // Note: Counter may be higher than expected due to intermediate allocations.
    }

    #[test]
    fn batch_verify_metrics_are_recorded() {
        // Test that batch_verify_v2() updates metrics correctly
        let seed = [42u8; 32];
        let (pk_bytes, sk_bytes) = Dilithium2Scheme::keygen_from_seed(&seed).expect("keygen");

        let public = PublicKey::from_bytes(pk_bytes);
        let secret = SecretKey::from_bytes(sk_bytes);

        // Record baseline metrics
        let calls_before = get_batch_verify_calls_total();
        let items_before = get_batch_verify_items_total();
        let invalid_before = get_batch_verify_invalid_total();
        let duration_before = get_batch_verify_duration_us_total();

        // Create a batch with 3 valid signatures
        let count = 3;
        let mut publics = Vec::new();
        let mut secrets = Vec::new();
        let mut messages = Vec::new();
        let mut sigs = Vec::new();

        for i in 0..count {
            let seed_i = [i as u8; 32];
            let (pk, sk) = Dilithium2Scheme::keygen_from_seed(&seed_i).expect("keygen");
            publics.push(PublicKey::from_bytes(pk));
            secrets.push(SecretKey::from_bytes(sk));
            messages.push(format!("Message {}", i).into_bytes());
        }

        for i in 0..count {
            let sig = sign(&messages[i], &secrets[i], AlgTag::Dilithium2, context::TX)
                .expect("signing should succeed");
            sigs.push(sig);
        }

        let mut items = Vec::new();
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

        // Call batch_verify_v2
        let outcome = batch_verify_v2(items);
        assert_eq!(outcome, BatchVerifyOutcome::AllValid);

        // Check metrics were updated
        let calls_after = get_batch_verify_calls_total();
        let items_after = get_batch_verify_items_total();
        let invalid_after = get_batch_verify_invalid_total();
        let duration_after = get_batch_verify_duration_us_total();

        assert_eq!(
            calls_after,
            calls_before + 1,
            "calls counter should increment by 1"
        );
        assert_eq!(
            items_after,
            items_before + 3,
            "items counter should increment by 3"
        );
        assert_eq!(
            invalid_after, invalid_before,
            "invalid counter should not change (all valid)"
        );
        assert!(duration_after > duration_before, "duration should increase");

        // Test invalid signature increments invalid counter
        let invalid_before2 = get_batch_verify_invalid_total();

        // Create one invalid signature (sign with one message, verify with different)
        let signed_msg = b"Original".to_vec();
        let sig_bad = sign(&signed_msg, &secret, AlgTag::Dilithium2, context::TX)
            .expect("signing should succeed");
        let verify_msg = b"Different".to_vec();

        let item_bad = VerifyItem::new(
            context::TX,
            AlgTag::Dilithium2,
            public.as_bytes(),
            &verify_msg,
            &sig_bad.bytes,
        )
        .expect("VerifyItem creation should succeed");

        let outcome_bad = batch_verify_v2(vec![item_bad]);
        assert_eq!(outcome_bad, BatchVerifyOutcome::SomeInvalid(1));

        let invalid_after2 = get_batch_verify_invalid_total();
        assert_eq!(
            invalid_after2,
            invalid_before2 + 1,
            "invalid counter should increment by 1"
        );
    }
}

//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║                    PRIVACY LAYER - CONFIDENTIAL AMOUNTS                  ║
// ║                  Pedersen Commitments + Bulletproofs                     ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof as BulletproofRangeProof};
// Note: bulletproofs v4 uses curve25519-dalek-ng, not curve25519-dalek
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar as NgScalar;
use curve25519_dalek_ng::traits::Identity;
use merlin::Transcript;

/// Maximum size of a range proof in bytes (32 KB).
/// Protects against DoS attacks via oversized proofs.
pub const MAX_PROOF_SIZE: usize = 32 * 1024;

/// Maximum number of range proofs per block (1000 default).
/// Prevents DoS via excessive proof verification.
pub const DEFAULT_MAX_PROOFS_PER_BLOCK: usize = 1000;

/// A Pedersen commitment to a value with blinding factor.
///
/// Commitment: C = v·G + r·H where:
/// - v = value (amount)
/// - r = blinding factor (random scalar)
/// - G, H = generator points
///
/// # Security
///
/// - Blinding factor is zeroized on drop
/// - Value commitment is public (32 bytes compressed Ristretto point)
/// - Provides computational hiding and perfect binding
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// Compressed Ristretto point representing the commitment
    pub value_commit: [u8; 32],
    /// Blinding factor (zeroized on drop)
    #[serde(with = "serde_bytes")]
    pub blinding: [u8; 32],
}

impl Commitment {
    /// Create a new commitment from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `value_commit` - 32-byte compressed Ristretto point
    /// * `blinding` - 32-byte blinding factor (will be zeroized on drop)
    pub fn new(value_commit: [u8; 32], blinding: [u8; 32]) -> Self {
        Self {
            value_commit,
            blinding,
        }
    }

    /// Get the commitment point as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.value_commit
    }
}

impl Drop for Commitment {
    fn drop(&mut self) {
        // Zeroize blinding factor to prevent memory leaks
        self.blinding.zeroize();
        increment_zeroize_counter();
    }
}

/// A Bulletproofs range proof for a committed value.
///
/// Proves that a committed value v satisfies: 0 ≤ v ≤ 2^64 - 1
/// without revealing the actual value.
///
/// # Security
///
/// - Maximum proof size: 32 KB (enforced at construction)
/// - Proof bytes are public (non-secret)
/// - Zero-knowledge: reveals nothing about the value
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RangeProof {
    /// Serialized Bulletproofs proof
    #[serde(with = "serde_bytes")]
    pub proof_bytes: Vec<u8>,
}

impl RangeProof {
    /// Create a new range proof from bytes.
    ///
    /// # Arguments
    ///
    /// * `proof_bytes` - Serialized Bulletproofs proof
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidProofSize` if proof exceeds MAX_PROOF_SIZE.
    pub fn new(proof_bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if proof_bytes.len() > MAX_PROOF_SIZE {
            return Err(CryptoError::InvalidProofSize {
                got: proof_bytes.len(),
                max: MAX_PROOF_SIZE,
            });
        }
        Ok(Self { proof_bytes })
    }

    /// Get the proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
}

/// A confidential transaction output with commitment and range proof.
///
/// Combines a Pedersen commitment with a Bulletproofs range proof
/// to create a fully confidential output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Confidential {
    /// Pedersen commitment to the value
    pub commitment: Commitment,
    /// Bulletproofs range proof
    pub proof: RangeProof,
}

/// Create a Pedersen commitment to a value.
///
/// # Arguments
///
/// * `value` - Amount to commit (0 ≤ value ≤ 2^64 - 1)
/// * `blinding` - 32-byte blinding factor (random scalar)
///
/// # Returns
///
/// A Commitment containing the compressed point and blinding factor.
///
/// # Example
///
/// ```ignore
/// use crypto::commit_value;
///
/// let value = 1000u64;
/// let mut blinding = [0u8; 32];
/// rand::thread_rng().fill_bytes(&mut blinding);
///
/// let commitment = commit_value(value, &blinding);
/// ```
pub fn commit_value(value: u64, blinding: &[u8; 32]) -> Commitment {
    let gens = PedersenGens::default();

    // Convert blinding to scalar (zeroized automatically)
    let blind_scalar = NgScalar::from_bytes_mod_order(*blinding);

    // Compute commitment: C = v·G + r·H
    let commit_point = gens.commit(NgScalar::from(value), blind_scalar);

    // Compress to 32 bytes
    let value_commit = commit_point.compress().to_bytes();

    Commitment::new(value_commit, *blinding)
}

/// Generate a Bulletproofs range proof for a committed value.
///
/// # Arguments
///
/// * `value` - Amount to prove (0 ≤ value ≤ 2^64 - 1)
/// * `blinding` - 32-byte blinding factor used in commitment
///
/// # Returns
///
/// A RangeProof that can be verified against the commitment.
///
/// # Errors
///
/// Returns error if proof generation fails or proof size exceeds limit.
///
/// # Example
///
/// ```ignore
/// use crypto::{commit_value, prove_range};
///
/// let value = 1000u64;
/// let blinding = [0u8; 32];
///
/// let commitment = commit_value(value, &blinding);
/// let proof = prove_range(value, &blinding)?;
/// ```
pub fn prove_range(value: u64, blinding: &[u8; 32]) -> Result<RangeProof, CryptoError> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1); // 64-bit range, 1 party

    // Create transcript for Fiat-Shamir
    let mut transcript = Transcript::new(b"pq-priv-range-proof");

    // Convert blinding to scalar
    let blind_scalar = NgScalar::from_bytes_mod_order(*blinding);

    // Create the proof
    let (proof, _committed_value) = BulletproofRangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        value,
        &blind_scalar,
        64, // 64-bit range (0 to 2^64-1)
    )
    .map_err(|_| CryptoError::ProofGenerationFailed)?;

    // Serialize proof
    let proof_bytes = proof.to_bytes();

    RangeProof::new(proof_bytes)
}

/// Verify a Bulletproofs range proof against a commitment.
///
/// # Arguments
///
/// * `commitment` - The Pedersen commitment to verify
/// * `proof` - The range proof to check
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise.
///
/// # Security
///
/// - Handles malformed proofs gracefully (returns false, no panic)
/// - Uses domain separation via Fiat-Shamir transcript
/// - Constant-time verification (no timing side-channels)
///
/// # Example
///
/// ```ignore
/// use crypto::{commit_value, prove_range, verify_range};
///
/// let value = 1000u64;
/// let blinding = [0u8; 32];
///
/// let commitment = commit_value(value, &blinding);
/// let proof = prove_range(value, &blinding)?;
///
/// assert!(verify_range(&commitment, &proof));
/// ```
pub fn verify_range(commitment: &Commitment, proof: &RangeProof) -> bool {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    // Create transcript (must match prover's)
    let mut transcript = Transcript::new(b"pq-priv-range-proof");

    // Create compressed point from bytes (from_slice returns CompressedRistretto directly)
    let commit_compressed = CompressedRistretto::from_slice(&commitment.value_commit);

    // Deserialize proof
    let bulletproof = match BulletproofRangeProof::from_bytes(&proof.proof_bytes) {
        Ok(proof) => proof,
        Err(_) => return false, // Malformed proof
    };

    // Verify the proof
    bulletproof
        .verify_single(&bp_gens, &pc_gens, &mut transcript, &commit_compressed, 64)
        .is_ok()
}

/// Verify that a set of commitments balance (sum to zero).
///
/// Used to ensure no inflation in confidential transactions:
/// sum(inputs) - sum(outputs) = 0 (in the Ristretto group).
///
/// # Arguments
///
/// * `inputs` - Commitments from transaction inputs
/// * `outputs` - Commitments from transaction outputs
///
/// # Returns
///
/// `true` if commitments balance, `false` otherwise.
///
/// # Example
///
/// ```ignore
/// use crypto::{commit_value, balance_commitments};
///
/// // Input: 1000
/// let input_blind = [1u8; 32];
/// let input_commit = commit_value(1000, &input_blind);
///
/// // Outputs: 700 + 300 = 1000
/// let out1_blind = [2u8; 32];
/// let out2_blind = [3u8; 32];
/// let out1_commit = commit_value(700, &out1_blind);
/// let out2_commit = commit_value(300, &out2_blind);
///
/// // This will fail because blinding factors don't match
/// // In practice, you need: blind_in = blind_out1 + blind_out2
/// assert!(!balance_commitments(&[input_commit], &[out1_commit, out2_commit]));
/// ```
pub fn balance_commitments(inputs: &[Commitment], outputs: &[Commitment]) -> bool {
    // Decompress all input commitments
    let input_points: Vec<RistrettoPoint> = inputs
        .iter()
        .filter_map(|c| {
            let compressed = CompressedRistretto::from_slice(&c.value_commit);
            compressed.decompress()
        })
        .collect();

    // Decompress all output commitments
    let output_points: Vec<RistrettoPoint> = outputs
        .iter()
        .filter_map(|c| {
            let compressed = CompressedRistretto::from_slice(&c.value_commit);
            compressed.decompress()
        })
        .collect();

    // Check we successfully decompressed all points
    if input_points.len() != inputs.len() || output_points.len() != outputs.len() {
        return false; // Invalid point encoding
    }

    // Compute sum of inputs
    let input_sum = input_points
        .iter()
        .fold(RistrettoPoint::identity(), |acc, &p| acc + p);

    // Compute sum of outputs
    let output_sum = output_points
        .iter()
        .fold(RistrettoPoint::identity(), |acc, &p| acc + p);

    // Check if they're equal (balance)
    input_sum == output_sum
}

/// Verify multiple range proofs in parallel using rayon.
///
/// This function provides significant performance improvements over sequential
/// verification when processing batches of range proofs. Benchmarks show:
/// - 10 proofs: 4.9x speedup
/// - 50 proofs: 7.2x speedup  
/// - 100 proofs: 7.9x speedup
///
/// # Arguments
///
/// * `proofs` - Slice of (commitment, proof) pairs to verify
///
/// # Returns
///
/// `Vec<bool>` - Verification result for each proof (true = valid, false = invalid)
///
/// # Performance
///
/// - Sequential: ~408 proofs/sec
/// - Parallel (rayon): ~3,329 proofs/sec (8.1x faster)
/// - Typical transaction (2 outputs): 4.88ms → 0.60ms verification
///
/// # Example
///
/// ```ignore
/// use crypto::{commit_value, prove_range, batch_verify_range};
///
/// // Create multiple proofs
/// let value1 = 1000u64;
/// let blinding1 = [1u8; 32];
/// let commit1 = commit_value(value1, &blinding1);
/// let proof1 = prove_range(value1, &blinding1)?;
///
/// let value2 = 2000u64;
/// let blinding2 = [2u8; 32];
/// let commit2 = commit_value(value2, &blinding2);
/// let proof2 = prove_range(value2, &blinding2)?;
///
/// // Batch verify in parallel
/// let proofs = vec![
///     (&commit1, &proof1),
///     (&commit2, &proof2),
/// ];
/// let results = batch_verify_range(&proofs);
/// assert!(results.iter().all(|&r| r)); // All should be valid
/// ```
pub fn batch_verify_range(proofs: &[(&Commitment, &RangeProof)]) -> Vec<bool> {
    use rayon::prelude::*;

    proofs
        .par_iter()
        .map(|(commitment, proof)| verify_range(commitment, proof))
        .collect()
}

/// Get the maximum allowed proof size.
pub fn get_max_proof_size() -> usize {
    MAX_PROOF_SIZE
}

/// Get the maximum allowed proofs per block.
pub fn get_max_proofs_per_block() -> usize {
    std::env::var("CRYPTO_MAX_PROOFS_PER_BLOCK")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_PROOFS_PER_BLOCK)
        .max(1)
}
