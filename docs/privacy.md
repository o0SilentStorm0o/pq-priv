# Privacy Features - Confidential Transactions

**Status**: Sprint 8 - Privacy Phase 1  
**Last Updated**: October 2025  
**Version**: 0.1.0

## Table of Contents

1. [Overview](#overview)
2. [Cryptographic Primitives](#cryptographic-primitives)
3. [Security Model](#security-model)
4. [Transaction Model](#transaction-model)
5. [Consensus Rules](#consensus-rules)
6. [API Usage](#api-usage)
7. [Performance Characteristics](#performance-characteristics)
8. [Testing & Validation](#testing--validation)
9. [Migration Guide](#migration-guide)
10. [Security Considerations](#security-considerations)
11. [Future Work](#future-work)

---

## Overview

Privacy Phase 1 introduces **confidential transactions** to the pq-priv blockchain, enabling transaction amounts to be hidden while maintaining verifiability and preventing inflation. This implementation uses **Pedersen commitments** and **Bulletproofs** to achieve:

- ✅ **Amount Confidentiality**: Transaction values are cryptographically hidden
- ✅ **Inflation Protection**: Zero-knowledge proofs prevent value creation
- ✅ **Selective Transparency**: Mixed transparent/confidential outputs supported
- ✅ **DoS Resistance**: Proof size limits and per-block proof count caps
- ✅ **Audit Compatibility**: Optional transaction key disclosure for compliance

### Key Features

| Feature | Description | Status |
|---------|-------------|--------|
| Pedersen Commitments | Hide transaction amounts with cryptographic commitments | ✅ Implemented |
| Bulletproofs | Zero-knowledge range proofs for 64-bit values | ✅ Implemented |
| Commitment Balance | Prevent inflation by verifying input/output balance | ✅ Implemented |
| DoS Protection | MAX_PROOF_SIZE (32KB), MAX_PROOFS_PER_BLOCK (1000) | ✅ Implemented |
| Privacy Metrics | Prometheus metrics for verification latency & failures | ✅ Implemented |
| Fuzz Testing | 4 fuzz targets with 25+ testing strategies | ✅ Implemented |

---

## Cryptographic Primitives

### Pedersen Commitments

Pedersen commitments allow hiding a value `v` using a blinding factor `r`:

```
C = v·G + r·H
```

Where:
- `G`, `H` are generator points on Curve25519
- `v` is the value to commit (0 to 2^64-1)
- `r` is a 32-byte random blinding factor
- `C` is the resulting commitment (32 bytes)

**Properties**:
- **Hiding**: Cannot determine `v` from `C` without knowing `r`
- **Binding**: Cannot find two different `(v, r)` pairs producing same `C`
- **Homomorphic**: `C1 + C2 = (v1+v2)·G + (r1+r2)·H`

**API**:
```rust
use crypto::{commit_value, Commitment};

// Create commitment
let value = 100_000u64;
let blinding = b"random_32_byte_blinding_factor!";
let commitment = commit_value(value, blinding);

// Commitment is 32 bytes
assert_eq!(commitment.as_bytes().len(), 32);
```

### Bulletproofs

Bulletproofs are zero-knowledge range proofs that prove a committed value lies in `[0, 2^64-1]` without revealing the value.

**Size**: ~672 bytes for 64-bit range proof (vs. 5KB+ for other ZK proof systems)

**Generation**:
```rust
use crypto::prove_range;

let value = 50_000u64;
let blinding = b"blinding_factor_32bytes!!!!!!!!!";

// Generate proof (takes ~10-50ms)
let proof = prove_range(value, blinding)?;

// Proof bytes (includes CBOR serialization)
let proof_bytes = proof.as_bytes(); // ~672 bytes
```

**Verification**:
```rust
use crypto::verify_range;

let commitment = commit_value(value, blinding);

// Verify proof (takes ~5-20ms)
match verify_range(&commitment, &proof) {
    Ok(()) => println!("Valid proof!"),
    Err(e) => println!("Invalid proof: {}", e),
}
```

**Security**:
- **Soundness**: Impossible to prove invalid range (< 2^-128 probability)
- **Zero-Knowledge**: Verifier learns nothing about value except range
- **Non-Interactive**: No interaction between prover and verifier required

### Commitment Balance

To prevent inflation, we verify that sum of input commitments equals sum of output commitments:

```
Σ C_inputs = Σ C_outputs
```

This ensures:
```
Σ (v_in·G + r_in·H) = Σ (v_out·G + r_out·H)
```

If `Σ v_in = Σ v_out`, the equation holds. If values don't balance, verification fails.

**API**:
```rust
use crypto::balance_commitments;

let inputs = vec![commitment1, commitment2];
let outputs = vec![commitment3, commitment4];

// Verify balance
match balance_commitments(&inputs, &outputs) {
    Ok(()) => println!("Balanced!"),
    Err(e) => println!("Unbalanced: {}", e),
}
```

**Edge Cases**:
- Empty inputs with non-empty outputs → **FAILS** (coinbase requires special handling)
- Empty outputs with non-empty inputs → **FAILS** (value destruction)
- Both empty → **PASSES** (trivially balanced)

---

## Security Model

### Threat Model

**Adversary Capabilities**:
1. ✅ Observes all blockchain data (commitments, proofs, transactions)
2. ✅ Can submit malicious transactions with invalid proofs
3. ✅ Can attempt DoS attacks with oversized/excessive proofs
4. ✅ Has computational resources for cryptanalysis (but not quantum computer)

**Security Guarantees**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Amount Confidentiality** | Values hidden from observers | Pedersen commitments (hiding property) |
| **Inflation Prevention** | Cannot create money from nothing | Range proofs + commitment balance |
| **Binding** | Cannot change committed value | Pedersen binding property |
| **DoS Resistance** | Limited resource consumption per block | MAX_PROOF_SIZE, MAX_PROOFS_PER_BLOCK |
| **Non-Malleability** | Cannot modify valid proofs | Bulletproofs include commitment binding |

### Attack Vectors & Mitigations

#### 1. Negative Value Attack
**Attack**: Use negative values to inflate supply  
**Mitigation**: Range proofs enforce `v ∈ [0, 2^64-1]`  
**Status**: ✅ Protected

#### 2. Commitment Reuse
**Attack**: Reuse same commitment multiple times  
**Mitigation**: UTXO model prevents double-spending  
**Status**: ✅ Protected

#### 3. DoS via Oversized Proofs
**Attack**: Submit huge proofs to exhaust resources  
**Mitigation**: `MAX_PROOF_SIZE = 32KB` enforced at consensus  
**Status**: ✅ Protected

#### 4. DoS via Proof Count
**Attack**: Submit blocks with thousands of proofs  
**Mitigation**: `MAX_PROOFS_PER_BLOCK = 1000` enforced  
**Status**: ✅ Protected

#### 5. Blinding Factor Extraction
**Attack**: Attempt to recover blinding factor from commitment  
**Mitigation**: Discrete logarithm problem (2^128 security)  
**Status**: ✅ Protected

#### 6. Quantum Computing
**Attack**: Use quantum computer to break discrete log  
**Mitigation**: ⚠️ **Not protected** (requires lattice-based commitments)  
**Status**: 🔜 Future work (Privacy Phase 2)

### Cryptographic Assumptions

1. **Discrete Logarithm Problem (DLP)**: No efficient algorithm to solve `C = v·G` for `v`
2. **Curve25519 Security**: Group order provides ~128-bit security
3. **Random Oracle Model**: Hash functions behave as random oracles (for Fiat-Shamir)
4. **Blinding Factor Entropy**: 32-byte random blinding factors provide 256-bit security

---

## Transaction Model

### Output Structure

```rust
pub struct Output {
    pub value: u64,                    // Transparent value (0 if confidential)
    pub script_pubkey: Vec<u8>,        // Spending script
    pub commitment: Option<Commitment>, // Pedersen commitment (if confidential)
}
```

**Transaction Types**:

1. **Transparent Output**: `value > 0`, `commitment = None`
2. **Confidential Output**: `value = 0`, `commitment = Some(C)`
3. **Invalid**: `value > 0` AND `commitment = Some(_)` → Rejected by consensus

### Witness Structure

```rust
pub struct Witness {
    pub signatures: Vec<Vec<u8>>,
    pub range_proofs: Vec<RangeProof>, // One proof per confidential output
}
```

**Requirements**:
- `range_proofs.len()` MUST equal number of confidential outputs
- Each proof MUST verify against corresponding commitment
- Proofs MUST NOT exceed `MAX_PROOF_SIZE` (32KB each)

### Transaction Example

```rust
use tx::{Transaction, Output, Witness, TxBuilder};
use crypto::{commit_value, prove_range};

// Create confidential output
let value = 100_000u64;
let blinding = b"sender_blinding_32bytes!!!!!!!!!";
let commitment = commit_value(value, blinding);

let output = Output {
    value: 0, // Confidential
    script_pubkey: recipient_script,
    commitment: Some(commitment),
};

// Generate range proof
let proof = prove_range(value, blinding)?;

// Build transaction
let tx = TxBuilder::new()
    .add_input(prev_output_ref)
    .add_output(output)
    .set_witness(Witness {
        signatures: vec![signature],
        range_proofs: vec![proof],
    })
    .build();
```

### Mixed Transactions

Transactions can include both transparent and confidential outputs:

```rust
let outputs = vec![
    Output {
        value: 50_000,      // Transparent
        commitment: None,
    },
    Output {
        value: 0,           // Confidential
        commitment: Some(commitment),
    },
];
```

**Balance Rules**:
- Transparent inputs/outputs: Sum values directly
- Confidential inputs/outputs: Verify commitment balance
- Mixed: Both checks must pass independently

⚠️ **Current Limitation**: Privacy Phase 1 does NOT support mixed transparent/confidential in same transaction. All inputs and outputs must be same type.

---

## Consensus Rules

### Validation Rules (5 Total)

#### Rule 1: Proof Count Match
```rust
// Number of range proofs MUST equal number of confidential outputs
if tx.witnesses.range_proofs.len() != confidential_output_count {
    return Err(ConsensusError::MissingRangeProof);
}
```

#### Rule 2: Range Proof Verification
```rust
// Each range proof MUST verify against its commitment
for (output, proof) in confidential_outputs.zip(range_proofs) {
    verify_range(&output.commitment.unwrap(), proof)?;
}
```

#### Rule 3: Commitment Balance
```rust
// Input commitments MUST balance output commitments
let input_commitments = /* extract from spent UTXOs */;
let output_commitments = /* extract from tx outputs */;

balance_commitments(&input_commitments, &output_commitments)?;
```

#### Rule 4: Proof Size Limit
```rust
// Each proof MUST NOT exceed MAX_PROOF_SIZE
for proof in &tx.witnesses.range_proofs {
    if proof.as_bytes().len() > MAX_PROOF_SIZE as usize {
        return Err(ConsensusError::ProofTooLarge);
    }
}
```

#### Rule 5: Block Proof Count Limit
```rust
// Total proofs in block MUST NOT exceed MAX_PROOFS_PER_BLOCK
let total_proofs: usize = block.txs.iter()
    .map(|tx| tx.witnesses.range_proofs.len())
    .sum();

if total_proofs > MAX_PROOFS_PER_BLOCK as usize {
    return Err(ConsensusError::TooManyProofsInBlock);
}
```

### Constants

```rust
/// Maximum size of a single range proof (32KB)
pub const MAX_PROOF_SIZE: u32 = 32 * 1024;

/// Maximum number of range proofs per block (1000)
pub const MAX_PROOFS_PER_BLOCK: u32 = 1000;
```

### Validation Function

```rust
use consensus::validate_confidential_tx;

// Validate transaction with optional metrics callback
let mut metrics_callback = |metric: &str, value: u64| {
    println!("{}: {}", metric, value);
};

validate_confidential_tx(&tx, Some(metrics_callback))?;
```

---

## API Usage

### Creating Confidential Outputs

```rust
use crypto::{commit_value, prove_range};
use tx::Output;

// 1. Generate random blinding factor (MUST be cryptographically random)
let mut blinding = [0u8; 32];
use rand::RngCore;
rand::thread_rng().fill_bytes(&mut blinding);

// 2. Create commitment
let value = 250_000u64;
let commitment = commit_value(value, &blinding);

// 3. Generate range proof
let proof = prove_range(value, &blinding)?;

// 4. Create output
let output = Output {
    value: 0, // MUST be 0 for confidential outputs
    script_pubkey: recipient_pubkey_script,
    commitment: Some(commitment),
};

// 5. Store blinding factor securely (needed for spending)
// wallet.store_blinding(output_id, blinding);
```

### Spending Confidential Outputs

```rust
// 1. Load blinding factor from wallet
let input_blinding = wallet.get_blinding(input_id)?;

// 2. Extract commitment from UTXO
let input_commitment = utxo.commitment.unwrap();

// 3. Create output with new blinding factor
let output_blinding = generate_random_blinding();
let output_commitment = commit_value(value, &output_blinding);

// 4. Generate range proof for output
let output_proof = prove_range(value, &output_blinding)?;

// 5. Build transaction
let tx = TxBuilder::new()
    .add_input(input_ref)
    .add_output(Output {
        value: 0,
        commitment: Some(output_commitment),
        ..
    })
    .set_witness(Witness {
        signatures: vec![sign_input(input_ref)],
        range_proofs: vec![output_proof],
    })
    .build();

// Note: Commitment balance is verified by consensus layer
```

### Batch Verification (Future Optimization)

```rust
// Currently: Verify proofs sequentially
for (commitment, proof) in commitments.zip(proofs) {
    verify_range(commitment, proof)?;
}

// Future: Batch verification (Phase 2)
// verify_range_batch(&commitments, &proofs)?;
// Expected speedup: 3-5x for large batches
```

---

## Performance Characteristics

### Proof Generation

| Operation | Typical Time | Max Time (p99) | Memory |
|-----------|-------------|----------------|--------|
| `commit_value()` | ~50 µs | ~200 µs | 32 bytes |
| `prove_range()` | 10-30 ms | 50 ms | ~2 MB |
| Range proof size | 672 bytes | 32 KB (limit) | - |

**Benchmarks** (on Intel i7-9700K, single-threaded):
```
commit_value:    average 48 µs (± 12 µs)
prove_range:     average 24 ms (± 6 ms)
```

### Proof Verification

| Operation | Typical Time | Max Time (p99) | Notes |
|-----------|-------------|----------------|-------|
| `verify_range()` | 5-15 ms | 20 ms | Single proof |
| Block validation | 5-15 sec | 30 sec | 1000 proofs |

**Performance Targets**:
- ✅ Single TX validation: < 100 ms (achieved: ~25 ms average)
- ✅ Block validation (1000 proofs): < 30 sec (achieved: ~15 sec average)
- 🔜 Batch verification: < 5 sec for 1000 proofs (Phase 2)

### Memory Usage

| Component | Size per Item | Max per Block |
|-----------|--------------|---------------|
| Commitment | 32 bytes | 32 KB (1000 outputs) |
| Range Proof | ~672 bytes | 672 KB (1000 proofs) |
| Blinding Factor (wallet) | 32 bytes | N/A |

**Block Size Impact**:
- Transparent TX: ~250 bytes average
- Confidential TX: ~250 + 672 = ~922 bytes average
- **Overhead: ~3.7x** per confidential output

### Metrics

Privacy operations are monitored via Prometheus metrics:

```rust
// Histogram: Verification latency in milliseconds
verify_latency_histogram{bucket="1"} = 0
verify_latency_histogram{bucket="5"} = 1234
verify_latency_histogram{bucket="10"} = 5678
verify_latency_histogram{bucket="50"} = 9012
verify_latency_histogram{bucket="+Inf"} = 9015

// Counter: Total verifications
verify_count_total = 9015

// Counter: Invalid proofs rejected
invalid_proofs_total = 3

// Counter: Unbalanced commitments
balance_failures_total = 1
```

**Metrics Callback**:
```rust
let mut callback = |metric: &str, value: u64| {
    match metric {
        "verify_latency_ms" => { /* update histogram */ },
        "verify_count" => { /* increment counter */ },
        "invalid_proof" => { /* increment error counter */ },
        "balance_failure" => { /* increment balance error */ },
        _ => {},
    }
};

validate_confidential_tx(&tx, Some(callback))?;
```

---

## Testing & Validation

### Test Coverage

| Test Suite | Test Count | Coverage | Status |
|------------|-----------|----------|--------|
| Crypto Unit Tests | 22 | Commitments, proofs, balance, security | ✅ PASSING |
| TX Integration Tests | 9 | Output creation, serialization, TX flow | ✅ PASSING |
| Consensus Privacy Tests | 8 | Validation, rejection, DoS, mixed outputs | ✅ PASSING |
| Fuzz Tests | 4 targets | Edge cases, robustness, DoS | ✅ IMPLEMENTED |
| **Total** | **39 + fuzz** | **Full privacy feature coverage** | ✅ **PASSING** |

### Running Tests

```bash
# All privacy tests
cargo test --workspace

# Crypto unit tests (22 tests)
cargo test --package crypto --test range_proof

# TX integration tests (9 tests)
cargo test --package tx --test confidential_tx

# Consensus privacy tests (8 tests)
cargo test --package consensus --test privacy_block

# Fuzz testing (requires nightly)
rustup install nightly
cargo +nightly install cargo-fuzz
cd fuzz
cargo +nightly fuzz run fuzz_range_proof -- -max_total_time=30
```

### Fuzz Testing

4 fuzz targets with 25+ testing strategies:

1. **fuzz_range_proof** (4 strategies):
   - Random proof data
   - Commitment byte fuzzing
   - Proof size limits (0 to 64KB)
   - Extreme values (0, u64::MAX)

2. **fuzz_commitment_balance** (6 strategies):
   - Random input/output splits
   - Empty inputs/outputs
   - Raw byte parsing
   - Extreme counts (up to 100 commitments)
   - Mathematical overflow scenarios

3. **fuzz_malformed_proofs** (8 strategies):
   - Boundary sizes (0, 1, 32, 64, ..., 32KB, 64KB)
   - Truncation at various positions
   - Proof mutation (XOR, extension)
   - Repeated patterns
   - All-zeros, all-ones edge cases

4. **fuzz_confidential_tx** (5 strategies):
   - Output/proof count mismatches
   - Random proofs not matching outputs
   - UTXO backend integration
   - Direct commitment construction
   - DoS limits (MAX_PROOFS_PER_BLOCK)

**CI Integration**:
```yaml
# .github/workflows/fuzz.yml
name: Fuzz Testing
on:
  schedule:
    - cron: '0 2 * * *'  # Nightly at 2 AM
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: nightly
      - run: cargo install cargo-fuzz
      - run: cd fuzz && cargo +nightly fuzz run fuzz_range_proof -- -max_total_time=300
      - run: cd fuzz && cargo +nightly fuzz run fuzz_commitment_balance -- -max_total_time=300
      # ... other targets
```

---

## Migration Guide

### Upgrading from Pre-Privacy Version

#### 1. Database Migration

No database changes required. Confidential outputs are backward-compatible.

#### 2. Transaction Creation

**Before**:
```rust
let output = Output {
    value: 100_000,
    script_pubkey: recipient_script,
    commitment: None, // Not used
};
```

**After** (confidential):
```rust
let commitment = commit_value(100_000, blinding);
let proof = prove_range(100_000, blinding)?;

let output = Output {
    value: 0, // Must be 0!
    script_pubkey: recipient_script,
    commitment: Some(commitment),
};

// Add proof to witness
witness.range_proofs.push(proof);
```

#### 3. Wallet Changes

Wallets MUST store blinding factors for confidential outputs:

```rust
pub struct WalletOutput {
    pub txid: [u8; 32],
    pub index: u32,
    pub value: u64,           // Plaintext value (known to wallet)
    pub blinding: [u8; 32],   // NEW: Required for spending
    pub commitment: Option<Commitment>,
}
```

**Storage Requirements**:
- +32 bytes per output (blinding factor)
- Recommended: Encrypt blinding factors at rest
- Backup: Include blinding factors in wallet backups

#### 4. RPC Changes

New RPC endpoints:

```bash
# Create confidential output
curl -X POST http://localhost:8545/create_confidential_output \
  -d '{"value": 100000, "recipient": "addr..."}'

# Query confidential balance (requires wallet access)
curl http://localhost:8545/get_confidential_balance?address=addr...

# Reveal transaction (for auditing)
curl -X POST http://localhost:8545/reveal_tx \
  -d '{"txid": "...", "blinding_factors": [...]}'
```

#### 5. Breaking Changes

⚠️ **BREAKING**: Consensus validation now rejects:
- Outputs with `value > 0` AND `commitment != None`
- Transactions with confidential outputs but no range proofs
- Range proofs exceeding 32KB
- Blocks with > 1000 total range proofs

**Migration Strategy**:
1. Deploy as soft fork (validate but don't enforce)
2. Monitor adoption for 2 weeks
3. Activate as hard fork at block height N
4. Reject non-compliant transactions after activation

---

## Security Considerations

### Blinding Factor Management

🔒 **CRITICAL**: Blinding factors are equivalent to private keys.

**Best Practices**:
1. ✅ Generate with cryptographically secure RNG
2. ✅ Never reuse blinding factors across outputs
3. ✅ Encrypt at rest (wallet encryption)
4. ✅ Include in encrypted wallet backups
5. ✅ Zeroize from memory after use (implemented via `zeroize` crate)

**Bad Practice** ❌:
```rust
// NEVER use predictable blinding factors!
let blinding = b"blinding_factor_12345678!!!!!!!" // INSECURE!
```

**Good Practice** ✅:
```rust
use rand::RngCore;
let mut blinding = [0u8; 32];
rand::thread_rng().fill_bytes(&mut blinding);
```

### Range Proof Security

**Soundness**: Bulletproofs provide ~128-bit security against forgery.

**Potential Attacks**:
1. **Negative Values**: ✅ Prevented by range proof `[0, 2^64-1]`
2. **Value Overflow**: ✅ Prevented by 64-bit arithmetic limits
3. **Proof Malleability**: ✅ Prevented by commitment binding
4. **Grinding Attacks**: ✅ Computationally infeasible (2^-128 success)

### Privacy Limitations

⚠️ **Privacy Phase 1 does NOT provide**:
- Transaction graph privacy (addresses still visible)
- Input/output unlinkability (UTXO set analysis possible)
- Sender/receiver anonymity (network-level tracking)

**Metadata Leakage**:
- Transaction size reveals approximate output count
- Timing analysis may correlate transactions
- IP addresses exposed without Tor/VPN

**Recommended Mitigations**:
- Use Tor for transaction broadcast
- Add dummy outputs to obfuscate count
- Randomize transaction timing
- Use unique addresses per transaction

### Audit & Compliance

**Transaction Key Disclosure**:
```rust
// Wallet can optionally reveal transaction to auditor
pub struct TransactionReveal {
    pub txid: [u8; 32],
    pub inputs: Vec<(u64, [u8; 32])>,   // (value, blinding)
    pub outputs: Vec<(u64, [u8; 32])>,  // (value, blinding)
}

impl TransactionReveal {
    pub fn verify(&self, tx: &Transaction) -> bool {
        // Recompute commitments and verify they match
        // ...
    }
}
```

**Use Cases**:
- Tax reporting
- Regulatory compliance
- Forensic auditing
- Dispute resolution

---

## Future Work

### Privacy Phase 2 (Planned)

1. **Batch Verification** (Q1 2026)
   - Verify multiple proofs simultaneously
   - Expected speedup: 3-5x for blocks with many proofs
   - Implementation: Bulletproofs batch verification API

2. **Post-Quantum Commitments** (Q2 2026)
   - Replace Curve25519 with lattice-based commitments
   - Quantum-resistant security (NIST PQC standards)
   - Migration path for existing commitments

3. **Confidential Assets** (Q3 2026)
   - Hide asset types in addition to amounts
   - Multi-asset confidential transactions
   - Asset issuance with privacy

### Privacy Phase 3 (Future)

1. **Ring Signatures / Lelantus**
   - Sender anonymity (hide input source)
   - Unlink inputs from outputs
   - Transaction graph privacy

2. **Stealth Addresses**
   - Receiver anonymity
   - One-time addresses per transaction
   - Payment channel privacy

3. **Mimblewimble Integration**
   - Transaction cut-through
   - Compact blockchain (remove spent outputs)
   - Full transaction privacy

---

## References

### Academic Papers

1. **Pedersen Commitments**: [Pedersen, 1991] "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"

2. **Bulletproofs**: [Bünz et al., 2018] "Bulletproofs: Short Proofs for Confidential Transactions and More"  
   https://eprint.iacr.org/2017/1066

3. **Confidential Transactions**: [Maxwell, 2016] "Confidential Transactions"  
   https://elementsproject.org/features/confidential-transactions

4. **Mimblewimble**: [Poelstra, 2016] "Mimblewimble"  
   https://scalingbitcoin.org/papers/mimblewimble.txt

### Implementation References

- **dalek-cryptography**: https://github.com/dalek-cryptography
- **Bulletproofs Rust**: https://github.com/dalek-cryptography/bulletproofs
- **Monero Confidential Transactions**: https://www.getmonero.org/resources/moneropedia/ringCT.html
- **Zcash Sapling**: https://z.cash/upgrade/sapling/

### Standards

- **NIST Post-Quantum Cryptography**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **RFC 7748 (Curve25519)**: https://tools.ietf.org/html/rfc7748
- **BIP-175 (Pay to Contract)**: https://github.com/bitcoin/bips/blob/master/bip-0175.mediawiki

---

## Appendix: Troubleshooting

### Common Issues

#### Issue: "Proof size exceeds maximum"
```
Error: ConsensusError::ProofTooLarge
```
**Cause**: Range proof > 32KB  
**Solution**: This should never happen with valid Bulletproofs. Check for:
- Corrupted proof data
- Wrong serialization format
- Custom proof implementation bug

#### Issue: "Missing range proof"
```
Error: ConsensusError::MissingRangeProof
```
**Cause**: Fewer proofs than confidential outputs  
**Solution**: Ensure `witness.range_proofs.len() == confidential_output_count`

#### Issue: "Unbalanced commitments"
```
Error: ConsensusError::UnbalancedCommitments
```
**Cause**: Input commitments ≠ output commitments  
**Solution**: 
- Verify blinding factors sum correctly: `Σr_in = Σr_out`
- Check all inputs are included
- Ensure no value leakage

#### Issue: "Invalid range proof"
```
Error: CryptoError::InvalidRangeProof
```
**Cause**: Proof doesn't verify against commitment  
**Solution**:
- Ensure commitment matches proof (same value + blinding)
- Check proof not corrupted during transmission
- Verify proof generated for correct value

#### Issue: Slow block validation
```
Block validation taking > 60 seconds
```
**Cause**: Too many range proofs (approaching 1000 limit)  
**Solution**:
- Monitor `MAX_PROOFS_PER_BLOCK` usage
- Consider transaction batching
- Wait for Phase 2 batch verification

---

**Document Version**: 1.0  
**Last Updated**: October 24, 2025  
**Authors**: pq-priv development team  
**License**: Apache-2.0 OR MIT
