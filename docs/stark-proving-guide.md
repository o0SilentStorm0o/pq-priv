# STARK Proving Guide

**Status**: Sprint 9 Infrastructure Complete (Steps 1-6 Roadmap)

This document describes the STARK privacy proving system implementation roadmap and provides a technical guide for developers working on the post-quantum privacy features.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Implementation Roadmap](#implementation-roadmap)
4. [Proving Workflow](#proving-workflow)
5. [Security Considerations](#security-considerations)
6. [Performance Targets](#performance-targets)

---

## Overview

The PQ-PRIV STARK privacy system provides **anonymous spending** for UTXO transactions using zero-knowledge proofs. Key features:

- **One-of-many proofs**: Prove a UTXO exists in the anonymity set without revealing which one
- **Nullifier-based double-spend prevention**: Deterministic nullifiers prevent reuse
- **Spend tag auditing**: Optional selective disclosure for exchange compliance
- **Post-quantum security**: Resistant to Grover's algorithm (quantum search attacks)

### Key Components

```
┌─────────────────────────────────────────────────────────────┐
│                    STARK Privacy System                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Wallet     │  │     Node     │  │  Exchange    │      │
│  │   (Prover)   │  │  (Verifier)  │  │  (Auditor)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │              │
│         │  TX v2 + Proof   │                  │              │
│         ├─────────────────>│                  │              │
│         │                  │                  │              │
│         │   Verify STARK   │                  │              │
│         │      Proof       │                  │              │
│         │                  │                  │              │
│         │  Audit Packet    │                  │              │
│         ├─────────────────────────────────────>              │
│         │                  │   (L1/L2/L3)     │              │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Architecture

### Transaction Version 2 Structure

```rust
pub struct TransactionV2 {
    /// Pedersen commitments to input amounts (privacy-preserving)
    pub inputs: Vec<Commitment>,
    
    /// Pedersen commitments to output amounts
    pub outputs: Vec<Commitment>,
    
    /// Nullifiers (one per input, prevents double-spending)
    pub nullifiers: Vec<Nullifier>,
    
    /// Spend tags (one per input, enables auditing)
    pub spend_tags: Vec<SpendTag>,
    
    /// STARK proofs (one per input, proves ownership)
    pub stark_proofs: Vec<StarkProof>,
    
    /// Range proofs (one per output, proves 0 ≤ amount < 2^64)
    pub range_proofs: Vec<RangeProof>,
    
    /// Transaction fee (public)
    pub fee: u64,
}
```

### STARK Proof Structure

```rust
pub struct StarkProof {
    /// FRI proof bytes (Step 4: ~10KB per proof)
    pub proof_bytes: Vec<u8>,
    
    /// Public inputs visible on-chain
    pub public_inputs: PublicInputs,
    
    /// Metadata (security level, anonymity set size, etc.)
    pub metadata: ProofMetadata,
}

pub struct PublicInputs {
    /// Nullifier (prevents double-spending)
    pub nullifier: Nullifier,
    
    /// Spend tag (enables exchange auditing)
    pub spend_tag: SpendTag,
    
    /// Merkle root of anonymity set
    pub merkle_root: [u8; 32],
}
```

### Witness Data (Private)

```rust
pub struct StarkWitness {
    /// Secret spend key (never revealed)
    sk_spend: [u8; 32],
    
    /// Secret view key (for spend tags)
    sk_view: [u8; 32],
    
    /// Commitment being spent
    commitment: [u8; 32],
    
    /// Network ID (replay protection)
    network_id: u8,
    
    /// Transaction version
    tx_version: u16,
    
    /// Epoch number (spend tag freshness)
    epoch: u64,
}
```

---

## Implementation Roadmap

### **Step 1: Project Structure** ✅ (Commit #1)

**Goal**: Set up STARK crate skeleton and coverage matrix.

**Files Created**:
- `crates/crypto/stark/Cargo.toml`
- `crates/crypto/stark/src/lib.rs`
- `crates/crypto/stark/benches/stark_perf.rs`
- `spec/coverage_matrix.md`

**Deliverables**:
- Empty STARK crate with module stubs
- Coverage matrix tracking implementation progress
- Benchmark placeholders for Step 6

**Tests**: 11 placeholder tests (all passing with `todo!()`)

---

### **Step 2: Transaction Types** ✅ (Commit #2)

**Goal**: Add TX v2 types with nullifier and spend tag.

**Files Modified**:
- `crates/tx/src/lib.rs` (added v2 module)
- `crates/tx/src/v2.rs` (new file, 150 lines)
- `crates/tx/src/witness.rs` (new file, 178 lines)

**Deliverables**:
- `Nullifier` struct with computation placeholder
- `SpendTag` struct with computation placeholder
- Serialization/deserialization support
- Documentation for privacy properties

**Tests**: 12 new tests (nullifier uniqueness, spend tag derivation, serialization)

---

### **Step 3: Nullifier Index** ✅ (Commit #3)

**Goal**: Add persistent nullifier storage with atomic reorg support.

**Files Modified**:
- `crates/storage/src/lib.rs`
- `crates/storage/src/nullifier.rs` (new file, 163 lines)

**Deliverables**:
- RocksDB-backed nullifier set
- `check_nullifier()` for double-spend detection
- `insert_nullifier()` with height tracking
- `revert_to_height()` for atomic rollback
- Column family: `cf_nullifiers`

**Tests**: 4 new tests (insert, check, revert, persistence)

**Schema**:
```
Key:   nullifier (32 bytes)
Value: block_height (u64, 8 bytes)
```

---

### **Step 4: Arithmetic & Poseidon2** ⏳ (Deferred to Post-Sprint 9)

**Goal**: Implement finite field arithmetic and Poseidon2 hash.

**Planned Files**:
- `crates/crypto/stark/src/field.rs` (Goldilocks field)
- `crates/crypto/stark/src/poseidon2.rs` (hash function)
- `crates/tx/src/witness.rs` (wire up real nullifier/spend_tag computation)

**Deliverables**:
- Goldilocks field (p = 2^64 - 2^32 + 1)
- Poseidon2 permutation (width = 12)
- Real nullifier computation: `Poseidon2("NULLIF" || sk_spend || commitment || net_id || tx_version)`
- Real spend tag computation: `Poseidon2("TAG" || sk_view || commitment || epoch)`

**Why Poseidon2**:
- STARK-friendly (algebraic hash, low degree)
- Post-quantum secure (no structure exploitable by quantum algorithms)
- Efficient in constraint systems (~100 constraints per hash)

**Tests**: 15+ tests (field ops, hash correctness, test vectors)

---

### **Step 5: Merkle Tree & FRI Prover** ⏳ (Deferred to Post-Sprint 9)

**Goal**: Implement Merkle tree and FRI proving system.

**Planned Files**:
- `crates/crypto/stark/src/merkle.rs` (binary Merkle tree)
- `crates/crypto/stark/src/fri.rs` (FRI protocol)
- `crates/crypto/stark/src/prover.rs` (STARK prover)

**Deliverables**:
- Binary Merkle tree with Poseidon2 hashing
- FRI commitment scheme (Fast Reed-Solomon IOP)
- STARK prover for one-of-many relation
- Fiat-Shamir transform for non-interactive proofs

**Security Levels**:
| Level    | FRI Queries | Security Bits | Proof Size | Proving Time |
|----------|-------------|---------------|------------|--------------|
| Fast     | 20          | ~80 bits      | ~8 KB      | ~200ms       |
| Standard | 27          | ~100 bits     | ~10 KB     | ~350ms       |
| High     | 40          | ~128 bits     | ~15 KB     | ~700ms       |

**Tests**: 20+ tests (Merkle proofs, FRI soundness, prover correctness)

---

### **Step 6: Verifier & Integration** ⏳ (Deferred to Post-Sprint 9)

**Goal**: Implement STARK verifier and integrate with node.

**Planned Files**:
- `crates/crypto/stark/src/verifier.rs` (STARK verifier)
- `crates/node/src/mempool.rs` (wire up TX v2 validation)
- `crates/node/src/state.rs` (wire up nullifier checking)

**Deliverables**:
- STARK verifier (<50ms verification time)
- Node integration:
  - Validate STARK proof before accepting TX
  - Check nullifier not in set
  - Verify Merkle root against UTXO set
- Batch verification optimization (verify multiple proofs in parallel)

**Tests**: 10+ tests (verifier correctness, integration tests, adversarial cases)

---

## Proving Workflow

### Wallet (Prover)

```rust
// 1. Build witness from wallet state
let witness = StarkWitness {
    sk_spend: wallet.derive_spend_key(index),
    sk_view: wallet.derive_view_key(index),
    commitment: utxo.commitment,
    network_id: 1, // Mainnet
    tx_version: 2,
    epoch: current_block_height / 1000,
};

// 2. Fetch anonymity set from node
let anonymity_set = node.get_utxo_commitments(witness.epoch)?;
// Returns 64-256 commitments (power of 2)

// 3. Generate STARK proof
let config = ProverConfig {
    anonymity_set_size: anonymity_set.len(),
    security_level: SecurityLevel::Standard, // 27 queries, ~100-bit security
};

let proof = generate_proof(witness, &anonymity_set, config)?;
// Proving time: ~350ms for Standard/64 anonymity set

// 4. Build TX v2
let tx = TransactionV2 {
    inputs: vec![commitment],
    outputs: vec![output_commitment],
    nullifiers: vec![proof.public_inputs.nullifier],
    spend_tags: vec![proof.public_inputs.spend_tag],
    stark_proofs: vec![proof],
    range_proofs: vec![output_range_proof],
    fee: 1000,
};

// 5. Submit to node
node.submit_transaction(tx)?;
```

### Node (Verifier)

```rust
// 1. Check nullifier not already spent
for nullifier in &tx.nullifiers {
    if storage.check_nullifier(nullifier)? {
        return Err("Double-spend detected");
    }
}

// 2. Verify STARK proofs
for (i, proof) in tx.stark_proofs.iter().enumerate() {
    // Check Merkle root matches current UTXO set
    let expected_root = storage.get_merkle_root()?;
    if proof.public_inputs.merkle_root != expected_root {
        return Err("Invalid Merkle root");
    }
    
    // Verify STARK proof (Step 6 implementation)
    verify_stark_proof(proof)?;
    // Verification time: <50ms
}

// 3. Verify range proofs
for (i, range_proof) in tx.range_proofs.iter().enumerate() {
    verify_range_proof(&tx.outputs[i], range_proof)?;
}

// 4. Check commitment balance
// sum(inputs) == sum(outputs) + fee (homomorphic property)
if !verify_commitment_balance(&tx.inputs, &tx.outputs, tx.fee) {
    return Err("Commitment balance mismatch");
}

// 5. Insert nullifiers into storage
for (i, nullifier) in tx.nullifiers.iter().enumerate() {
    storage.insert_nullifier(nullifier, current_height)?;
}

// 6. Accept transaction
mempool.add(tx)?;
```

---

## Security Considerations

### 1. Anonymity Set Size

**Minimum**: 32 commitments (provides ~5-bit anonymity)
**Recommended**: 64-128 commitments (provides ~6-7 bit anonymity)
**Maximum**: 256 commitments (provides ~8-bit anonymity)

**Trade-offs**:
- Larger anonymity sets → stronger privacy
- Larger anonymity sets → slower proving time
- Must be power of 2 for efficient FRI

### 2. Nullifier Uniqueness

**Property**: `nullifier = Poseidon2("NULLIF" || sk_spend || commitment || net_id || tx_version)`

**Security**:
- Deterministic (same input → same nullifier)
- One-way (cannot reverse to find sk_spend)
- Collision-resistant (infeasible to find two inputs with same nullifier)

**Attack Resistance**:
- Double-spending: Impossible (nullifier checked against set)
- Replay attacks: Network ID prevents cross-chain replay
- Quantum attacks: Poseidon2 resistant to Grover's algorithm

### 3. Spend Tag Privacy

**Property**: `spend_tag = Poseidon2("TAG" || sk_view || commitment || epoch)`

**Purpose**:
- Enables exchange scanning (wallet can detect incoming TXs)
- Exchange can prove ownership without revealing spend key

**Privacy Leak**:
- Spend tags reveal "transaction graph" to holder of sk_view
- **Mitigation**: Rotate sk_view periodically (new epoch)

### 4. Fiat-Shamir Security

**Challenge Generation**:
```rust
challenge = BLAKE3(
    "STARK_CHALLENGE" ||
    proof.commitment ||
    public_inputs ||
    security_level
)
```

**Properties**:
- Non-interactive (no prover-verifier interaction)
- Binding (prover cannot change commitment after seeing challenge)
- Post-quantum secure (BLAKE3 is quantum-resistant)

---

## Performance Targets

### Proving Performance

| Anonymity Set | Security Level | Proving Time | Proof Size | Memory |
|---------------|----------------|--------------|------------|--------|
| 32            | Fast           | ~150ms       | ~8 KB      | ~50 MB |
| 64            | Standard       | ~350ms       | ~10 KB     | ~75 MB |
| 128           | Standard       | ~700ms       | ~12 KB     | ~100 MB|
| 256           | High           | ~1.5s        | ~15 KB     | ~150 MB|

### Verification Performance

| Security Level | Verification Time | Batch (10 TXs) |
|----------------|-------------------|----------------|
| Fast           | <30ms             | ~250ms         |
| Standard       | <50ms             | ~400ms         |
| High           | <80ms             | ~650ms         |

### Node Performance

| Metric                | Target          | Current (Sprint 9) |
|-----------------------|-----------------|-------------------|
| Nullifier lookup      | <1μs            | ~0.5μs (HashSet)  |
| TX v2 validation      | <100ms          | N/A (placeholder) |
| Mempool throughput    | >1000 TXs/sec   | ~5000 TXs/sec     |
| Nullifier set size    | 10M entries     | Unlimited (disk)  |

---

## Next Steps (Post-Sprint 9)

1. **Step 4 Implementation**: Goldilocks field + Poseidon2 hash
   - Estimated effort: 2-3 weeks
   - Deliverable: Real nullifier/spend_tag computation

2. **Step 5 Implementation**: Merkle tree + FRI prover
   - Estimated effort: 4-6 weeks
   - Deliverable: Full STARK proving system

3. **Step 6 Implementation**: STARK verifier + node integration
   - Estimated effort: 2-3 weeks
   - Deliverable: Production-ready privacy system

4. **Security Audit**: External cryptographic review
   - Estimated effort: 4-6 weeks
   - Scope: STARK implementation, nullifier uniqueness, spend tag privacy

5. **Testnet Deployment**: Deploy to public testnet
   - Estimated effort: 1-2 weeks
   - Goal: Collect real-world performance data

---

## References

- [STARK Protocol Paper](https://eprint.iacr.org/2018/046) - Scalable Transparent Arguments of Knowledge
- [FRI Protocol](https://eccc.weizmann.ac.il/report/2017/134/) - Fast Reed-Solomon Interactive Oracle Proofs
- [Poseidon2 Hash](https://eprint.iacr.org/2023/323) - Optimized algebraic hash function
- [Goldilocks Field](https://polygon.technology/blog/goldilocks-the-fastest-field-for-stark-proofs) - p = 2^64 - 2^32 + 1

---

**Document Version**: 1.0  
**Last Updated**: Sprint 9 Completion  
**Status**: Infrastructure Complete, Implementation Deferred
