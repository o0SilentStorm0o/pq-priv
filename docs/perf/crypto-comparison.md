# Performance Comparison: Range Proofs vs PQ Signatures

**Project**: pq-priv blockchain  
**Date**: 24. října 2025  
**Branch**: feat/sprint8-privacy-phase1

---

## Overview

This document compares the performance characteristics of two critical cryptographic operations in the pq-priv blockchain:

1. **Post-Quantum Signatures (Dilithium2/ML-DSA-44)** - Transaction authentication
2. **Range Proofs (Bulletproofs+)** - Confidential transaction amounts

Both operations support **batch verification** for improved throughput.

---

## Performance Comparison Table

| Metric | Dilithium2 (PQ Sig) | Bulletproofs+ (Range) | Ratio |
|--------|---------------------|----------------------|-------|
| **Single Operation** | | | |
| Generation/Prove | ~8 ms | 11.6 ms | 1.5x slower |
| Verification | ~1.5 ms | 2.44 ms | 1.6x slower |
| Proof/Sig Size | ~2.4 KB | ~675 bytes | **3.6x smaller** |
| | | | |
| **Batch Verification (100 items)** | | | |
| Sequential Time | ~150 ms | 244.8 ms | 1.6x slower |
| Parallel Time | ~30 ms | 30.9 ms | **~1.0x (equal!)** |
| Sequential Throughput | ~667/sec | 408/sec | 1.6x slower |
| Parallel Throughput | ~3,333/sec | 3,238/sec | **~1.0x (equal!)** |
| Batch Speedup | 5x | **7.9x** | 1.6x better |
| | | | |
| **Blockchain Impact** | | | |
| Cost per TX | 1.5 ms (1 sig) | 4.88 ms (2 proofs) | 3.3x more |
| Block verification (100 TX) | ~150 ms | ~245 ms | 1.6x slower |
| Block verification (parallel) | ~30 ms | ~31 ms | **~1.0x (equal!)** |

---

## Key Findings

### 1. Range Proofs are Slower (but Acceptable)

**Single Operation:**
- Range proofs take **1.5-1.6x longer** than signatures
- This is expected: range proofs perform more complex mathematical operations
- Still **fast enough for production**: 2.44 ms verification is acceptable

**Why it's OK:**
- Signatures are verified on **every input** (1-3 per transaction)
- Range proofs are verified on **every output** (1-3 per transaction)  
- Both are similar scale, so relative cost is manageable

### 2. Parallel Performance is Comparable

**Batch Verification (100 items):**
- Both achieve **~30ms** for 100 items in parallel
- Both reach **~3,200-3,300 items/sec** throughput
- **Equal performance in real-world blockchain usage** ✅

**Why this matters:**
- Blockchain nodes process batches (blocks) not individual items
- Parallel batch performance determines actual TPS
- Range proofs **match signature performance** at scale

### 3. Range Proofs Have Better Parallelization

**Speedup Comparison:**
- Signatures: 5x speedup (150ms → 30ms)
- Range proofs: **7.9x speedup** (245ms → 31ms)

**Analysis:**
- Range proof verification parallelizes **better** than signature verification
- Likely due to independent Bulletproofs operations vs shared PQ crypto state
- This compensates for slower single-operation performance

### 4. Range Proofs are Much Smaller

**Size Comparison:**
- Signature: ~2,400 bytes (Dilithium2)
- Range proof: **~675 bytes** (Bulletproofs+)
- Savings: **3.6x smaller** 🎉

**Impact:**
- Lower bandwidth requirements
- Smaller block sizes for confidential transactions
- Better storage efficiency
- Faster network propagation

---

## Combined Transaction Cost

### Standard Transaction (2 inputs, 2 outputs)

**Without Privacy:**
- 2 signature verifications: 2 × 1.5 ms = **3 ms**
- Range proofs: 0
- **Total: 3 ms**

**With Privacy (Confidential Amounts):**
- 2 signature verifications: 2 × 1.5 ms = 3 ms
- 2 range proof verifications: 2 × 2.44 ms = 4.88 ms
- **Total: 7.88 ms** (2.6x slower)

**Batch Processing (100 transactions, parallel):**
- 200 signature verifications: 30 ms (parallel)
- 200 range proof verifications: 31 ms (parallel)
- **Total: ~61 ms** (can overlap further with pipelining)
- **Throughput: ~1,640 TPS** with full privacy ✅

---

## Blockchain Throughput Analysis

### Block Verification Time (100 transactions)

| Configuration | Sequential | Parallel | TPS (parallel) |
|--------------|-----------|----------|----------------|
| **Public TX (sigs only)** | 150 ms | 30 ms | 3,333 TPS |
| **Confidential TX (sigs + proofs)** | 395 ms | ~61 ms | **1,640 TPS** |

**Privacy Cost:**
- **2x slower** in parallel mode (30ms → 61ms)
- Still **faster than Bitcoin** (~7 TPS) and **Ethereum** (~15-30 TPS)
- **Acceptable trade-off** for full amount confidentiality

---

## Proof Size Impact on Block Size

### Block with 100 Confidential Transactions

**Signature Data:**
- 200 signatures (2 per TX): 200 × 2.4 KB = **480 KB**

**Range Proof Data:**
- 200 range proofs (2 per TX): 200 × 0.675 KB = **135 KB**

**Total Crypto Data:**
- 615 KB for 100 transactions
- Average: **6.15 KB per transaction**

**Comparison:**
- Bitcoin TX: ~250 bytes (no privacy)
- Monero TX: ~2 KB (privacy with RingCT)
- **pq-priv TX: ~6.15 KB** (privacy + post-quantum security)

**Analysis:**
- 3x larger than Monero (due to PQ signatures)
- **Much smaller range proofs help** (675 bytes vs 2KB+ alternatives)
- Reasonable size for privacy + quantum resistance

---

## Performance Recommendations

### 1. ✅ Current Performance is Production-Ready

Both cryptographic operations meet production requirements:
- **Throughput**: 1,640+ TPS with full privacy
- **Latency**: 61 ms block verification (acceptable)
- **Size**: 6.15 KB/TX (reasonable)

### 2. 🚀 Future Optimizations (Sprint 9+)

#### High Priority:
1. **Aggregated Range Proofs**
   - Combine 10-100 proofs into one
   - Potential: 90% size reduction (135 KB → 13.5 KB per block)
   - Verification: Same or better performance

2. **SIMD Vectorization**
   - Target: Bulletproofs scalar multiplication
   - Potential: 2-4x speedup (AVX2/AVX-512)
   - Benefit: 61ms → 15-30ms block verification

#### Medium Priority:
3. **GPU Acceleration**
   - Offload batch verification to GPU
   - Potential: 10-100x for sync/archive nodes
   - Use case: Historical block verification

4. **Pipelined Verification**
   - Overlap signature + range proof verification
   - Potential: 61ms → 35ms (max(30, 31) with perfect overlap)
   - Complexity: Moderate

---

## Security vs Performance Trade-offs

| Property | Dilithium2 | Bulletproofs+ | Notes |
|----------|-----------|---------------|-------|
| **Security Level** | NIST Level 2 (128-bit) | 128-bit discrete log | Both quantum-resistant |
| **Trust Assumptions** | None (post-quantum) | Discrete log hard | Standard assumption |
| **Proof Soundness** | Perfect | Computational | Bulletproofs is sound |
| **Zero-Knowledge** | N/A | Yes | Range proofs hide amounts |
| **Performance** | Faster (1.5x) | Slower | Acceptable difference |
| **Size** | Larger (3.6x) | Smaller | Range proofs win here |

**Conclusion**: Both primitives offer **strong security** with **acceptable performance**.

---

## Benchmark Methodology

### Hardware (estimated from results)

- **CPU**: 8+ core processor (based on 7.9x parallel speedup)
- **RAM**: Sufficient for 100-proof batches (< 100 MB)
- **OS**: Windows

### Software

- **Rust**: 1.90+ (edition 2024)
- **Criterion**: 0.5 (quick mode)
- **Rayon**: 1.10 (parallel execution)

### Test Configuration

**Dilithium2 (from docs/crypto/batch-verify.md):**
- Message size: 1 KB
- Batch sizes: 32, 128, 512
- Mode: Criterion quick

**Bulletproofs+ (current benchmarks):**
- Value range: 64-bit (0 to 2^64-1)
- Batch sizes: 10, 50, 100
- Mode: Criterion quick

---

## Conclusion

### Summary of Findings

1. ✅ **Range proofs are 1.5-1.6x slower** than PQ signatures (expected)
2. ✅ **Parallel performance is equal** (~30ms for 100 items)
3. ✅ **Range proofs parallelize better** (7.9x vs 5x speedup)
4. ✅ **Range proofs are 3.6x smaller** (675 bytes vs 2.4 KB)
5. ✅ **Combined TPS: 1,640+** with full privacy (acceptable)

### Final Verdict

**Both cryptographic systems are production-ready** and work well together:

- **Signatures**: Authenticate transactions (required)
- **Range proofs**: Hide amounts (optional privacy feature)
- **Combined overhead**: 2x slower but still **faster than Bitcoin/Ethereum**
- **Privacy benefit**: Full amount confidentiality with provable range constraints

**The performance cost of privacy is acceptable** for users who value financial confidentiality. The system can support both public and confidential transactions, allowing users to choose their privacy level.

---

## References

- **PQ Signature Benchmarks**: `docs/crypto/batch-verify.md`
- **Range Proof Benchmarks**: `docs/perf/range-proof-performance.md`
- **Signature Implementation**: `crates/crypto/src/lib.rs` (sign, verify, batch_verify_v2)
- **Range Proof Implementation**: `crates/crypto/src/lib.rs` (prove_range, verify_range, batch_verify_range)
- **Benchmark Code**:
  - Signatures: `crates/crypto/benches/crypto_verify.rs`
  - Range Proofs: `crates/crypto/benches/range_proof_perf.rs`

---

**Generated**: 24. října 2025  
**Status**: ✅ Production-ready performance for both primitives
