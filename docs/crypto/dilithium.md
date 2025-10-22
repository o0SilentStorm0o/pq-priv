# CRYSTALS-Dilithium Integration

## Overview

CRYSTALS-Dilithium is a lattice-based digital signature scheme standardized by NIST as part of the Post-Quantum Cryptography (PQC) standardization process. It provides strong security guarantees against both classical and quantum adversaries.

## Why Dilithium?

### Advantages

1. **Quantum Resistance**: Based on the hardness of Module Learning With Errors (Module-LWE), resistant to Shor's algorithm
2. **NIST Standard**: One of the three algorithms selected for standardization (FIPS 204)
3. **Performance**: Fast signing and verification (~2-5 ms)
4. **Deterministic Signatures**: Supports deterministic signing for reproducibility
5. **Mature Implementation**: Multiple high-quality implementations available

### Comparison with Alternatives

| Scheme | Security Level | Public Key | Secret Key | Signature | Sign (ms) | Verify (ms) |
|--------|----------------|------------|------------|-----------|-----------|-------------|
| Ed25519 | Classical 128 | 32 B | 32 B | 64 B | 0.03 | 0.08 |
| **Dilithium2** | **NIST L2** | **1312 B** | **2528 B** | **2420 B** | **2.4** | **1.0** |
| Dilithium3 | NIST L3 | 1952 B | 4000 B | 3293 B | 3.8 | 1.6 |
| Dilithium5 | NIST L5 | 2592 B | 4864 B | 4595 B | 5.5 | 2.0 |
| SPHINCS+-128s | NIST L1 | 32 B | 64 B | 7856 B | 900 | 15 |

**Dilithium2** offers the best balance of security, performance, and signature size for blockchain use.

## Parameter Sets

### Dilithium2 (Default)

- **Security Level**: NIST Level 2 (equivalent to AES-128 against quantum attacks)
- **Public Key Size**: 1,312 bytes
- **Secret Key Size**: 2,528 bytes
- **Signature Size**: 2,420 bytes
- **Performance**: ~2.4 ms signing, ~1.0 ms verification (on modern CPU)

**Rationale**: Provides adequate security for the foreseeable future while keeping signature sizes manageable.

### Dilithium3 (Future)

- **Security Level**: NIST Level 3 (equivalent to AES-192)
- **Larger keys and signatures**: 30-40% increase
- **Use case**: High-security applications requiring extra margin

### Dilithium5 (Future)

- **Security Level**: NIST Level 5 (equivalent to AES-256)
- **Largest keys and signatures**: 2x Dilithium2
- **Use case**: Ultra-paranoid settings or long-term archives

## Implementation Strategy

### Phase 1: Basic Integration (Sprint 5)

1. Add `pqcrypto-dilithium` dependency
2. Implement `SignatureScheme` trait for `Dilithium2`
3. Wire into `tx` and `consensus` validation
4. Comprehensive unit tests

### Phase 2: Optimization (Future)

1. AVX2/AVX-512 optimizations (via `liboqs`)
2. Batch verification for block validation
3. Signature caching
4. Hardware acceleration (if available)

### Phase 3: Advanced Features (Future)

1. Threshold signatures (multi-party signing)
2. Deterministic vs randomized signing trade-offs
3. Side-channel hardening for HSM deployment

## Library Selection

### Primary: `pqcrypto-dilithium`

```toml
[dependencies]
pqcrypto-dilithium = { version = "0.8", features = ["std"] }
```

**Pros**:
- Pure Rust wrapper around NIST reference implementation
- Well-maintained by the PQClean project
- Clean API: `keypair()`, `sign()`, `verify()`

**Cons**:
- Reference implementation (not optimized)
- ~3x slower than AVX2 assembly

### Alternative: `liboqs-rust`

```toml
[dependencies]
oqs = { version = "0.10", features = ["dilithium"] }
```

**Pros**:
- Highly optimized (AVX2/AVX-512 assembly)
- Comprehensive algorithm support (Dilithium + SPHINCS+ + others)

**Cons**:
- Requires C compiler and OpenSSL
- More complex build process
- Heavier dependency

**Decision**: Start with `pqcrypto-dilithium` for simplicity. Migrate to `liboqs-rust` if performance profiling shows signature verification as a bottleneck.

## API Design

### Trait Implementation

```rust
use pqcrypto_dilithium::dilithium2;

pub struct Dilithium2;

impl SignatureScheme for Dilithium2 {
    const ALG: AlgTag = AlgTag::Dilithium2;
    const NAME: &'static str = "Dilithium2";
    const PUBLIC_KEY_BYTES: usize = dilithium2::PUBLIC_KEY_BYTES;
    const SECRET_KEY_BYTES: usize = dilithium2::SECRET_KEY_BYTES;
    const SIGNATURE_BYTES: usize = dilithium2::SIGNATURE_BYTES;

    fn keygen_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // Expand seed using ChaCha20, then derive keypair
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (pk, sk) = dilithium2::keypair_with_rng(&mut rng);
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = dilithium2::SecretKey::from_bytes(secret)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = dilithium2::detached_sign(msg, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let pk = dilithium2::PublicKey::from_bytes(public);
        let signature = dilithium2::DetachedSignature::from_bytes(sig);
        match (pk, signature) {
            (Ok(pk), Ok(sig)) => dilithium2::verify_detached_signature(&sig, msg, &pk).is_ok(),
            _ => false,
        }
    }
}
```

## Transaction Witness Format

### Before (Ed25519 Stub)

```rust
pub struct Witness {
    pub range_proofs: Vec<u8>,
    pub stamp: u64,
    pub extra: Vec<u8>,
}
```

### After (Dilithium-Ready)

```rust
pub struct Witness {
    pub alg_tag: AlgTag,           // NEW: Algorithm identifier
    pub range_proofs: Vec<u8>,
    pub stamp: u64,
    pub extra: Vec<u8>,
}

pub struct Input {
    // ... existing fields ...
    pub pq_signature: Signature,   // Already contains alg_tag
}
```

**Note**: `Input.pq_signature` already contains `alg_tag`, so signatures are self-describing.

## Validation Flow

### Transaction Validation

```rust
pub fn validate_tx_signature(input: &Input, msg: &[u8]) -> Result<(), TxError> {
    let sig = &input.pq_signature;
    match sig.alg {
        AlgTag::Ed25519 => {
            #[cfg(feature = "dev_stub_signing")]
            return Ed25519Stub::verify(input.spend_public.as_bytes(), msg, &sig.bytes)
                .then_some(())
                .ok_or(TxError::InvalidSignature);
            
            #[cfg(not(feature = "dev_stub_signing"))]
            return Err(TxError::InvalidSignature); // Ed25519 disabled in production
        }
        AlgTag::Dilithium2 => {
            Dilithium2::verify(input.spend_public.as_bytes(), msg, &sig.bytes)
                .then_some(())
                .ok_or(TxError::InvalidSignature)
        }
        _ => Err(TxError::InvalidSignature),
    }
}
```

### Block Validation

```rust
pub fn validate_block(block: &Block) -> Result<(), ConsensusError> {
    // ... existing checks ...
    
    for tx in &block.txs {
        for input in &tx.inputs {
            let msg = tx::input_auth_message(input, &binding_hash);
            validate_tx_signature(input, &msg)?;
        }
    }
    
    Ok(())
}
```

## Performance Considerations

### Expected Throughput

| Operation | Ed25519 | Dilithium2 | Slowdown |
|-----------|---------|------------|----------|
| Sign | 30,000/s | 417/s | 72x |
| Verify | 12,500/s | 1,000/s | 12.5x |

**Impact on Block Validation**:
- 1000 tx/block with 2 inputs each = 2000 signature verifications
- Ed25519: 0.16 seconds
- Dilithium2: 2 seconds

**Mitigation**:
1. Parallel verification (Rayon): ~4x speedup on 4-core CPU
2. Signature caching (mempool pre-validation)
3. Batch verification (future)

### Memory Footprint

**Per Transaction** (average 2 inputs, 2 outputs):
- Ed25519 signatures: 2 × 64 = 128 bytes
- Dilithium2 signatures: 2 × 2420 = 4,840 bytes

**37x larger signatures**, but blockchain is already dominated by range proofs and stealth blobs.

### Blockchain Size Impact

**Assuming**:
- 1000 tx/day
- 2 inputs per tx (average)
- Dilithium2 signatures: 2420 bytes each

**Daily growth**: 1000 × 2 × 2420 = 4.84 MB/day from signatures

**Yearly growth**: 1.77 GB/year (manageable)

## Testing Strategy

### Unit Tests

```rust
#[test]
fn dilithium2_sign_verify_roundtrip() {
    for i in 0..1000 {
        let seed = [i as u8; 32];
        let (pk, sk) = Dilithium2::keygen_from_seed(&seed).unwrap();
        let msg = format!("test message {}", i);
        let sig = Dilithium2::sign(&sk, msg.as_bytes()).unwrap();
        assert!(Dilithium2::verify(&pk, msg.as_bytes(), &sig));
    }
}

#[test]
fn dilithium2_rejects_forged_signature() {
    let (pk1, _) = Dilithium2::keygen_from_seed(&[1; 32]).unwrap();
    let (_, sk2) = Dilithium2::keygen_from_seed(&[2; 32]).unwrap();
    let msg = b"forgery";
    let sig = Dilithium2::sign(&sk2, msg).unwrap();
    assert!(!Dilithium2::verify(&pk1, msg, &sig));
}
```

### Integration Tests

```rust
#[test]
fn validate_block_with_dilithium_signatures() {
    let km = KeyMaterial::random();
    let spend = km.derive_spend_keypair(0);
    
    // Build transaction with Dilithium2 signature
    let input = build_signed_input(
        [0; 32], 0, &spend,
        vec![0x42], &binding_hash
    );
    
    let tx = TxBuilder::new()
        .add_input(input)
        .add_output(sample_output())
        .build();
    
    let block = Block {
        header: sample_header(),
        txs: vec![tx],
    };
    
    validate_block(&block).expect("block should be valid");
}
```

### Property-Based Tests

```rust
#[quickcheck]
fn dilithium2_verify_is_deterministic(msg: Vec<u8>) -> bool {
    let (pk, sk) = Dilithium2::keygen_from_seed(&[42; 32]).unwrap();
    let sig = Dilithium2::sign(&sk, &msg).unwrap();
    let result1 = Dilithium2::verify(&pk, &msg, &sig);
    let result2 = Dilithium2::verify(&pk, &msg, &sig);
    result1 == result2
}
```

## Security Audit Checklist

- [ ] Key generation uses cryptographically secure RNG
- [ ] Secret keys never logged or printed
- [ ] Signature verification is constant-time
- [ ] Algorithm tags validated before deserialization
- [ ] Buffer overflows prevented (signature size checks)
- [ ] Side-channel resistance (delegated to underlying library)
- [ ] Test vectors from NIST reference implementation

## Migration Path

### Phase 1: Ed25519 → Dilithium2

1. Deploy nodes with both algorithms supported
2. New transactions use Dilithium2
3. Old blocks with Ed25519 remain valid

### Phase 2: Deprecate Ed25519

1. After 1 year (or consensus threshold)
2. New nodes reject Ed25519 signatures
3. Old blocks remain valid (historical data)

### Future: Algorithm Agility

If Dilithium2 is compromised:
1. Add new `AlgTag` (e.g., `Dilithium3` or `FalconXXX`)
2. Soft fork to migrate validators
3. Users generate new keys with updated algorithm

## References

- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [CRYSTALS-Dilithium Official Website](https://pq-crystals.org/dilithium/)
- [PQClean: Post-Quantum Cryptography Library](https://github.com/PQClean/PQClean)
- [pqcrypto-dilithium Crate](https://crates.io/crates/pqcrypto-dilithium)
- [liboqs: Open Quantum Safe](https://github.com/open-quantum-safe/liboqs)
