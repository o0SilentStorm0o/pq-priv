# Performance Targets (Commit #6)

## STARK Privacy Operations

### Proof Generation (`prove_one_of_many`)

Target latency thresholds by anonymity set size:

| Anonymity Set | Target (ms) | Max Acceptable (ms) | Notes |
|--------------|-------------|---------------------|-------|
| 32           | < 300       | 500                 | Minimum privacy set |
| 64           | < 500       | 800                 | **Standard config** |
| 128          | < 800       | 1200                | Enhanced privacy |
| 256          | < 1200      | 2000                | Maximum privacy |

**Rationale**: Proof generation is ~5-10ms per Merkle tree layer + 100ms FRI commitment.
- Merkle depth: log₂(N) layers
- N=64: 6 layers × 8ms + 100ms FRI = ~148ms baseline
- Add 3x overhead for constraint system = ~450ms target

### Proof Verification (`verify_one_of_many`)

Target latency thresholds:

| Anonymity Set | Target (ms) | Max Acceptable (ms) | Notes |
|--------------|-------------|---------------------|-------|
| 32           | < 30        | 60                  | ~21ms baseline |
| 64           | < 50        | 100                 | **Standard config** |
| 128          | < 80        | 150                 | ~26ms baseline |
| 256          | < 120       | 200                 | ~28ms baseline |

**Rationale**: Verification is ~1-2ms per Merkle layer + 20ms FRI queries.
- Much faster than prove (no witness generation)
- Critical for mempool throughput (max 10 pending TX v2 per peer)

### Batch Verification

Target throughput for parallel verification:

| Batch Size | Target (ms) | Throughput (tx/s) | Notes |
|-----------|-------------|-------------------|-------|
| 10        | < 300       | 33 tx/s           | Small batch |
| 50        | < 1500      | 33 tx/s           | Medium batch |
| 100       | < 3000      | 33 tx/s           | **Large batch** |

**Rationale**: Batch verification enables ~30-50 tx/s for TX v2 mempool processing.
- Linear scaling (no batch optimization yet)
- Future: Fiat-Shamir batching could reduce to O(log N)

## Proof Size

Target proof sizes by anonymity set:

| Anonymity Set | Target (KB) | Max Acceptable (KB) | Components |
|--------------|-------------|---------------------|------------|
| 32           | < 8         | 12                  | Merkle path (5×32B) + FRI (7KB) |
| 64           | < 10        | 15                  | **Merkle path (6×32B) + FRI (9KB)** |
| 128          | < 12        | 18                  | Merkle path (7×32B) + FRI (11KB) |
| 256          | < 15        | 22                  | Merkle path (8×32B) + FRI (14KB) |

**Components**:
- Merkle authentication path: log₂(N) × 32 bytes
- FRI proof: ~7-15KB (depends on field size, query count)
- Constraint witness: ~1-2KB

## CPU Fee Policy (Mempool)

Fee multiplier rationale (from Commit #5):

```
Base fee: 10 sat/kb
TX v2 fee: 50 sat/kb (5× multiplier)
```

**Justification**:
- STARK verify: ~5-10ms (50-100× slower than ECDSA signature verify ~0.1ms)
- Conservative 5× multiplier accounts for CPU cost
- Prevents DoS via expensive TX v2 validation

## Prometheus Metrics

### STARK Prove Metrics

```prometheus
# Histogram: pqpriv_stark_prove_ms
# Buckets: [100, 250, 500, 1000, 2000, 5000, 10000, +Inf] ms
pqpriv_stark_prove_ms_bucket{le="500"} 245
pqpriv_stark_prove_ms_count 245
pqpriv_stark_prove_ms_sum 112500.0

# Counter: pqpriv_stark_prove_count
pqpriv_stark_prove_count 245
```

### STARK Verify Metrics

```prometheus
# Histogram: pqpriv_stark_verify_ms
# Buckets: [10, 25, 50, 100, 200, 500, 1000, +Inf] ms
pqpriv_stark_verify_ms_bucket{le="50"} 1523
pqpriv_stark_verify_ms_count 1523
pqpriv_stark_verify_ms_sum 76150.0

# Counter: pqpriv_stark_verify_count
pqpriv_stark_verify_count 1523

# Counter: pqpriv_stark_invalid_total
pqpriv_stark_invalid_total 3
```

### Proof Size Metrics

```prometheus
# Histogram: pqpriv_stark_proof_size_bytes
# Buckets: [1KB, 5KB, 10KB, 20KB, 50KB, 100KB, 200KB, +Inf]
pqpriv_stark_proof_size_bytes_bucket{le="10240"} 245
pqpriv_stark_proof_size_bytes_count 245
pqpriv_stark_proof_size_bytes_sum 2457600

# Gauge: pqpriv_stark_proof_size_bytes_last
pqpriv_stark_proof_size_bytes_last 9856
```

## CI Regression Checks

### Alert Thresholds

Benchmarks fail if performance degrades by >150% (1.5×):

```yaml
alert-threshold: '150%'
fail-on-alert: true
```

**Examples**:
- Prove (64-elem): Baseline 450ms → Alert at 675ms → Fail at 800ms
- Verify (64-elem): Baseline 50ms → Alert at 75ms → Fail at 100ms

### Benchmark Tracking

- Runs on every push to `main` and `feat/privacy/stark-phase`
- Stores historical data in GitHub Actions cache
- Comments on PRs with performance delta
- Auto-fails if thresholds exceeded

## Testing Strategy

### Unit Tests
- Mock STARK prover/verifier for fast tests
- Verify metrics recording (counters, histograms)
- Test bucket assignment logic

### Integration Tests
- End-to-end prove/verify cycle
- Measure actual latency (not just simulation)
- Verify proof size bounds

### Benchmark Tests
- Criterion.rs for statistical rigor
- Varying anonymity sets (32, 64, 128, 256)
- Batch verification throughput
- Memory profiling (future)

## Future Optimizations

1. **Fiat-Shamir Batching**: Reduce batch verify from O(N) to O(log N)
2. **Plonky3 Backend**: 10-100× faster proving with PLONK
3. **GPU Acceleration**: Offload FRI commitment to GPU
4. **Proof Compression**: STARK-to-SNARK recursion (1KB proofs)

## References

- Commit #5: Mempool validation (CPU fee policy)
- Commit #6: CI benches + Prometheus metrics (this doc)
- `/crates/crypto/stark/benches/stark_perf.rs`: Benchmark implementation
- `/crates/node/src/metrics.rs`: Prometheus metrics
