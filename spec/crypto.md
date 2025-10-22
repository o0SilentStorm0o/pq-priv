# Cryptography Specification

## Overview

The PQ-PRIV blockchain employs post-quantum cryptographic primitives to ensure long-term security against both classical and quantum adversaries. This document specifies the signature schemes, key derivation, and cryptographic commitments used throughout the system.

## Signature Schemes

### Trait-Based Architecture

All signature schemes implement the `SignatureScheme` trait, providing a uniform interface:

```rust
pub trait SignatureScheme {
    const ALG: AlgTag;
    const NAME: &'static str;
    const PUBLIC_KEY_BYTES: usize;
    const SECRET_KEY_BYTES: usize;
    const SIGNATURE_BYTES: usize;

    fn keygen_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}
```

### Algorithm Tags

Each signature scheme is identified by an `AlgTag`:

| Tag | Value | Algorithm | Status |
|-----|-------|-----------|--------|
| `Ed25519` | 0x00 | Ed25519 | Dev stub only (feature `dev_stub_signing`) |
| `Dilithium2` | 0x01 | CRYSTALS-Dilithium2 | ✅ **Implemented** (Sprint 5) |
| `Dilithium3` | 0x02 | CRYSTALS-Dilithium3 | Future |
| `Dilithium5` | 0x03 | CRYSTALS-Dilithium5 | Future |
| `SphincsPlus` | 0x10 | SPHINCS+ | Future |

### Ed25519 (Development Stub)

**Security Level**: Classical 128-bit (NOT quantum-resistant)

**Key Sizes**:
- Public key: 32 bytes
- Secret key: 32 bytes
- Signature: 64 bytes

**Usage**: Only for testing and development. Enabled with the `dev_stub_signing` feature flag (default in dev builds).

**Implementation**: Uses `ed25519-dalek` with deterministic key derivation via ChaCha20 expansion.

### CRYSTALS-Dilithium2 ✅

**Security Level**: NIST Level 2 (quantum-resistant, equivalent to AES-128)

**Key Sizes**:
- Public key: 1,312 bytes
- Secret key: 2,560 bytes
- Signature: 2,420 bytes

**Usage**: Primary signature scheme for production deployment.

**Implementation**: Implemented using `pqcrypto-dilithium` (v0.5). Based on Module-LWE hardness assumption, standardized as NIST FIPS 204.

**Performance**: ~2ms signing, ~1ms verification (reference implementation).

**Status**: ✅ Fully implemented and tested (Sprint 5 complete)

### CRYSTALS-Dilithium3 / Dilithium5

**Security Levels**: NIST Level 3 / Level 5 (quantum-resistant)

**Status**: Reserved for future use. Higher security levels with larger key/signature sizes.

### SPHINCS+

**Security Level**: Stateless hash-based signatures

**Status**: Reserved for future use as a conservative fallback option.

## Key Derivation

### Master Seed

All keys derive from a 32-byte master seed using BLAKE3 key derivation:

```rust
pub struct KeyMaterial {
    master_seed: Vec<u8>, // 32 bytes
}
```

### Deterministic Key Derivation

Keys are derived using labeled BLAKE3 KDF with a 32-bit index:

```
seed = BLAKE3-KDF(master_seed, label, index)
keypair = SignatureScheme::keygen_from_seed(seed)
```

Labels:
- `"scan"`: For stealth address scanning keys
- `"spend"`: For transaction authorization keys

### ChaCha20 Expansion

To avoid low-entropy keys, seeds are expanded using ChaCha20:

```rust
let mut rng = ChaCha20Rng::from_seed(seed);
let mut sk_bytes = [0u8; 32];
rng.fill_bytes(&mut sk_bytes);
```

## Commitments

### Value Commitments

Values are committed using SHA3-256:

```
commitment(value, blinding) = SHA3-256(value || blinding)
```

Where:
- `value`: 8-byte little-endian u64
- `blinding`: arbitrary-length byte array

### Link Tags

Link tags prevent double-spending by linking spends to specific keys:

```
link_tag = BLAKE3("link-tag-v0" || spend_public || nonce)
```

Where:
- `spend_public`: Public spend key
- `nonce`: Random nonce (prevents linkability across transactions)

## Hashing

### BLAKE3

Used for:
- Key derivation (BLAKE3-KDF)
- Link tag computation
- General-purpose hashing

### SHA3-256

Used for:
- Value commitments
- Compatibility with existing cryptographic protocols

## Security Considerations

### Key Storage

- Master seeds MUST be stored with file permissions 0600
- Secret keys MUST NOT be logged or transmitted in plaintext
- Memory containing secret keys SHOULD be zeroed after use (future enhancement)

### Algorithm Migration

The trait-based design allows seamless algorithm migration:

1. Old blocks retain their original `alg_tag` in witness/input signatures
2. New transactions can use updated algorithms
3. Validators check `alg_tag` and dispatch to appropriate verifier

### Quantum Resistance

- **Ed25519**: NOT quantum-resistant. Use only for testing.
- **Dilithium2+**: Quantum-resistant per NIST PQC standards.
- **SPHINCS+**: Conservative quantum-resistant option (stateless).

### Side-Channel Resistance

- Signature verification MUST be constant-time (delegated to underlying libraries)
- Key generation uses cryptographically secure RNGs (OS entropy + ChaCha20)

## Testing Requirements

Each signature scheme implementation MUST pass:

1. **Round-trip**: Sign and verify 1000 random messages
2. **Forgery resistance**: Verify rejects signatures from different keys
3. **Malleability**: Verify rejects corrupted signature bytes
4. **Algorithm mismatch**: Verify rejects signatures with wrong `alg_tag`

## Sprint 5 Implementation Status ✅

**Completed**:
- ✅ Trait-based signature scheme API
- ✅ Extended AlgTag with Dilithium2/3/5, Ed25519, SPHINCS+
- ✅ Ed25519Stub implementation (dev_stub_signing feature)
- ✅ Dilithium2 full implementation
- ✅ High-level sign()/verify() dispatch functions
- ✅ Integration with tx and node crates
- ✅ Comprehensive test suite (14 crypto tests, 70 total)
- ✅ Documentation (spec/crypto.md, docs/crypto/dilithium.md)

**Branches**:
- `feat/crypto-traits` - Trait-based API foundation
- `feat/crypto-dilithium` - Dilithium2 implementation

## Future Enhancements

- [ ] Deterministic keygen with liboqs (current: uses system entropy)
- [ ] AVX2/AVX-512 optimizations via liboqs
- [ ] Batch signature verification for block validation
- [ ] Memory zeroization for secret keys
- [ ] Dilithium3/5 parameter sets
- [ ] SPHINCS+ stateless signatures
- [ ] Hardware security module (HSM) integration
- [ ] Threshold signatures
- [ ] BLS aggregation for block validation optimization
