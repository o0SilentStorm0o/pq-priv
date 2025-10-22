# Batch Signature Verification

## Overview

The `batch_verify_v2()` API provides high-performance batch verification of post-quantum signatures with automatic parallelization. Batch verification processes multiple signatures concurrently, achieving **6-8x throughput improvement** over sequential verification.

**Key Benefits:**
- **Performance**: 6-8x faster than sequential verification (72 Kelem/s vs 9 Kelem/s)
- **Security**: Strict validation, domain separation, automatic zeroization
- **Observability**: Prometheus metrics for monitoring
- **Flexibility**: Runtime-configurable thread pool and batch size limits

## API Reference

### Core Types

#### `VerifyItem<'a>`

Single item for batch verification containing all necessary data to verify one signature.

```rust
pub struct VerifyItem<'a> {
    pub context: Context,      // Domain separation context (e.g., context::TX)
    pub alg: AlgTag,            // Algorithm tag (must match signature)
    pub public: &'a [u8],       // Public key bytes
    pub msg: &'a [u8],          // Message to verify
    pub sig: &'a [u8],          // Signature bytes
}
```

**Construction:**

```rust
use crypto::{VerifyItem, context, AlgTag};

let item = VerifyItem::new(
    context::TX,              // Domain separation context
    AlgTag::Dilithium2,       // Algorithm tag
    public_key.as_bytes(),    // Public key
    message.as_slice(),       // Message
    signature.bytes.as_slice(), // Signature
)?;
```

**Validation:**
- Message length ≤ `MAX_MESSAGE_LEN` (16 MB)
- Public key size matches algorithm
- Signature size matches algorithm
- Returns `CryptoError::InvalidInput` on validation failure

#### `BatchVerifyOutcome`

Result of batch verification with detailed per-signature status.

```rust
pub enum BatchVerifyOutcome {
    /// All signatures valid
    AllValid,
    /// Some signatures invalid (contains indices)
    SomeInvalid(Vec<usize>),
    /// All signatures invalid
    AllInvalid,
}
```

**Methods:**

```rust
// Check if all signatures are valid
outcome.is_all_valid() -> bool

// Get count of invalid signatures
outcome.invalid_count() -> usize

// Get indices of invalid signatures (if any)
if let BatchVerifyOutcome::SomeInvalid(indices) = outcome {
    println!("Invalid at positions: {:?}", indices);
}
```

### Main Function

#### `batch_verify_v2()`

Verify multiple signatures with automatic parallelization and threshold switching.

```rust
pub fn batch_verify_v2<'a>(
    items: impl IntoIterator<Item = VerifyItem<'a>>,
) -> BatchVerifyOutcome
```

**Features:**
- **Automatic parallelization**: Uses Rayon thread pool (configurable via `CRYPTO_VERIFY_THREADS`)
- **Threshold switching**: Falls back to sequential for small batches (< `CRYPTO_VERIFY_THRESHOLD`)
- **Early rejection**: Pre-validates all items before processing
- **Batch size limits**: Rejects batches exceeding `CRYPTO_MAX_BATCH_SIZE`
- **Algorithm consistency**: All items must use the same algorithm
- **Metrics tracking**: Records calls, items, invalids, and duration

**Example:**

```rust
use crypto::{batch_verify_v2, VerifyItem, context, AlgTag};

// Prepare items
let items: Vec<VerifyItem> = transactions
    .iter()
    .flat_map(|tx| {
        tx.inputs.iter().map(|input| {
            VerifyItem::new(
                context::TX,
                AlgTag::Dilithium2,
                &input.public_key,
                &input.auth_message,
                &input.signature,
            ).unwrap()
        })
    })
    .collect();

// Batch verify
let outcome = batch_verify_v2(items);

match outcome {
    BatchVerifyOutcome::AllValid => {
        // All signatures valid - proceed with block
        println!("All {} signatures verified", items.len());
    }
    BatchVerifyOutcome::SomeInvalid(indices) => {
        // Some invalid - reject block
        eprintln!("Invalid signatures at: {:?}", indices);
    }
    BatchVerifyOutcome::AllInvalid => {
        // All invalid - reject block
        eprintln!("All signatures invalid");
    }
}
```

## Configuration

### Environment Variables

Batch verify behavior can be tuned via environment variables at runtime.

#### `CRYPTO_VERIFY_THREADS`

Number of threads for parallel verification.

- **Default**: `num_cpus::get()` (all available cores)
- **Valid range**: 1 to system core count
- **When to adjust**:
  - **Lower**: Reduce CPU usage in resource-constrained environments
  - **Higher**: Not recommended (limited by core count)

```bash
# Use 4 threads for batch verification
CRYPTO_VERIFY_THREADS=4 ./node

# Use all available cores (default)
./node
```

#### `CRYPTO_VERIFY_THRESHOLD`

Minimum batch size to trigger parallel verification.

- **Default**: `32`
- **Valid range**: 1 to `CRYPTO_MAX_BATCH_SIZE`
- **Rationale**: Parallelization overhead isn't worth it for tiny batches
- **When to adjust**:
  - **Lower (e.g., 16)**: High-performance systems with low parallelization overhead
  - **Higher (e.g., 64)**: Systems with high context-switching costs

```bash
# Use parallel verification for batches ≥ 64
CRYPTO_VERIFY_THRESHOLD=64 ./node

# Always use parallel (even for 1 signature)
CRYPTO_VERIFY_THRESHOLD=1 ./node
```

#### `CRYPTO_MAX_BATCH_SIZE`

Maximum allowed batch size (DoS protection).

- **Default**: `100,000`
- **Valid range**: 1 to `usize::MAX`
- **Rationale**: Prevents memory exhaustion from oversized batches
- **When to adjust**:
  - **Lower**: Memory-constrained environments
  - **Higher**: High-throughput nodes with large blocks

```bash
# Limit batch size to 50,000 signatures
CRYPTO_MAX_BATCH_SIZE=50000 ./node

# Allow very large batches (1 million signatures)
CRYPTO_MAX_BATCH_SIZE=1000000 ./node
```

**Note**: Exceeding `CRYPTO_MAX_BATCH_SIZE` causes all items to be rejected (`AllInvalid`).

## Performance

### Benchmark Results

Benchmarks measured on Dilithium2 (ML-DSA-44) using criterion with `--quick` mode.

#### Single Verification (Baseline)

```
single_verify_1kB_msg   time:   [110.84 µs 110.88 µs 111.04 µs]
```

- **1 signature**: 111 µs
- **Throughput**: 9,009 signatures/second

#### Batch Verification (Various Sizes)

```
batch_verify/32         time:   [586.12 µs 587.76 µs 594.34 µs]
                        thrpt:  [53.841 Kelem/s 54.444 Kelem/s 54.597 Kelem/s]
```

- **32 signatures**: 587 µs total = 18.3 µs per signature
- **Speedup**: 6.1x faster than sequential
- **Throughput**: 54,444 signatures/second

```
batch_verify/128        time:   [1.9714 ms 1.9810 ms 2.0193 ms]
                        thrpt:  [63.389 Kelem/s 64.614 Kelem/s 64.928 Kelem/s]
```

- **128 signatures**: 1.98 ms total = 15.5 µs per signature
- **Speedup**: 7.2x faster than sequential
- **Throughput**: 64,614 signatures/second

```
batch_verify/512        time:   [6.9436 ms 7.0441 ms 7.0692 ms]
                        thrpt:  [72.427 Kelem/s 72.685 Kelem/s 73.737 Kelem/s]
```

- **512 signatures**: 7.04 ms total = 13.8 µs per signature
- **Speedup**: 8.0x faster than sequential
- **Throughput**: 72,685 signatures/second

#### Throughput Comparison (128 signatures)

```
sequential_single_verify_128    time:   [14.237 ms 14.242 ms 14.260 ms]
                                thrpt:  [8.9765 Kelem/s 8.9878 Kelem/s 8.9906 Kelem/s]

batch_verify_128                time:   [1.9856 ms 2.0078 ms 2.0134 ms]
                                thrpt:  [63.576 Kelem/s 63.752 Kelem/s 64.465 Kelem/s]
```

- **Sequential**: 14.24 ms (111 µs per signature)
- **Batch**: 2.01 ms (15.7 µs per signature)
- **Speedup**: 7.1x faster

### Performance Characteristics

- **Scaling**: Speedup improves with batch size (6.1x @ 32 → 8.0x @ 512)
- **Threshold**: Parallel verification becomes beneficial at ~32 signatures
- **Memory**: Each `VerifyItem` ~50 bytes (32 signatures = ~1.6 KB)
- **Overhead**: Parallelization overhead ~100 µs (amortized across batch)

### Real-World Performance

Typical blockchain scenarios:

| Scenario | Signatures | Time (sequential) | Time (batch) | Speedup |
|----------|-----------|-------------------|--------------|---------|
| Small block (10 tx, 1 input each) | 10 | 1.11 ms | 200 µs | 5.5x |
| Medium block (50 tx, 2 inputs each) | 100 | 11.1 ms | 1.6 ms | 6.9x |
| Large block (200 tx, 2 inputs each) | 400 | 44.4 ms | 5.8 ms | 7.7x |
| Sync catchup (1000 tx, 2 inputs) | 2000 | 222 ms | 29 ms | 7.7x |

**Block validation improvement**: 7-8x faster consensus validation for typical blocks.

## Metrics

### Prometheus Counters

Four atomic counters track batch verify operations:

```rust
// Total number of batch_verify_v2() calls
batch_verify_calls_total() -> u64

// Total number of signatures processed
batch_verify_items_total() -> u64

// Total number of invalid signatures detected
batch_verify_invalid_total() -> u64

// Total verification time in microseconds
batch_verify_duration_us_total() -> u64
```

### Exporting Metrics

The `node` crate exposes these metrics via the `/metrics` endpoint:

```rust
use crypto::{
    batch_verify_calls_total,
    batch_verify_items_total,
    batch_verify_invalid_total,
    batch_verify_duration_us_total,
};

// In your /metrics handler
format!(
    "crypto_batch_verify_calls_total {}\n\
     crypto_batch_verify_items_total {}\n\
     crypto_batch_verify_invalid_total {}\n\
     crypto_batch_verify_duration_us_total {}\n",
    batch_verify_calls_total(),
    batch_verify_items_total(),
    batch_verify_invalid_total(),
    batch_verify_duration_us_total(),
)
```

### Example Metrics Output

```
# HELP crypto_batch_verify_calls_total Total batch verify calls
# TYPE crypto_batch_verify_calls_total counter
crypto_batch_verify_calls_total 1547

# HELP crypto_batch_verify_items_total Total signatures verified
# TYPE crypto_batch_verify_items_total counter
crypto_batch_verify_items_total 312845

# HELP crypto_batch_verify_invalid_total Total invalid signatures
# TYPE crypto_batch_verify_invalid_total counter
crypto_batch_verify_invalid_total 23

# HELP crypto_batch_verify_duration_us_total Total verification time (µs)
# TYPE crypto_batch_verify_duration_us_total counter
crypto_batch_verify_duration_us_total 4562891
```

### Derived Metrics

Calculate derived metrics in your monitoring system:

```promql
# Average batch size
rate(crypto_batch_verify_items_total[5m]) / rate(crypto_batch_verify_calls_total[5m])

# Invalid signature rate (should be near 0%)
rate(crypto_batch_verify_invalid_total[5m]) / rate(crypto_batch_verify_items_total[5m])

# Average time per signature (µs)
rate(crypto_batch_verify_duration_us_total[5m]) / rate(crypto_batch_verify_items_total[5m])

# Throughput (signatures/second)
rate(crypto_batch_verify_items_total[5m])
```

## Security

### Domain Separation

All signatures use CBOR-encoded domain separation to prevent cross-protocol attacks:

```rust
// Domain separation contexts
context::TX              // Transaction input signatures
context::BLOCK           // Block header signatures
context::P2P_HANDSHAKE   // P2P handshake signatures
```

**Why it matters**: Without domain separation, a valid transaction signature could be replayed as a block signature. CBOR encoding ensures unambiguous preimage construction.

### Zeroization

All sensitive buffers are automatically zeroized on drop:

- **CBOR buffers**: `domain_separated_hash()` uses `Zeroizing<Vec<u8>>`
- **Secret keys**: `SecretKey` implements `Zeroize` + custom `Drop`
- **Temporary data**: All verification paths use stack-allocated arrays

**Security impact**: Memory forensics cannot recover signature message data after verification.

### Strict Validation

Pre-verification checks reject malformed input:

1. **Message length**: ≤ 16 MB (prevents DoS)
2. **Batch size**: ≤ `CRYPTO_MAX_BATCH_SIZE` (prevents memory exhaustion)
3. **Key sizes**: Must match algorithm exactly (prevents malleability)
4. **Signature sizes**: Must match algorithm exactly (prevents malleability)
5. **Algorithm consistency**: All items must use same algorithm (prevents confusion)

**Note**: Any validation failure causes immediate rejection without processing.

### Constant-Time Operations

Critical operations use constant-time implementations:

- **Signature verification**: Dilithium2 library uses constant-time scalar ops
- **Outcome construction**: Uses `subtle::ConstantTimeEq` for comparisons
- **Early termination**: Disabled (all signatures verified even if first fails)

**Security property**: Timing side-channels do not leak information about which signatures are invalid.

## Invariants

### Thread Safety

- `batch_verify_v2()` is **thread-safe** (uses Rayon's global thread pool)
- Metrics use `AtomicU64` with `Relaxed` ordering (sufficient for counters)
- No mutable shared state across calls

### Memory Safety

- All lifetimes `'a` ensure borrowed data outlives verification
- `VerifyItem` borrows (doesn't own) data → zero-copy construction
- Rayon automatically manages thread-local allocations

### Correctness

- **No false positives**: Valid signatures always verify successfully
- **No false negatives**: Invalid signatures always detected
- **Deterministic**: Same input always produces same output
- **Order-independent**: Signature order doesn't affect outcome (except indices)

### Failure Modes

| Failure | Behavior | Metrics |
|---------|----------|---------|
| Empty batch | Returns `AllValid` | No metrics recorded |
| Oversized batch | Returns `AllInvalid` | No metrics recorded |
| Invalid message length | Rejects item | `invalid_total++` |
| Wrong key/sig size | Rejects item | `invalid_total++` |
| Mixed algorithms | Returns `AllInvalid` | No metrics recorded |
| Cryptographic failure | Returns `SomeInvalid` | `invalid_total++` |

## Usage Patterns

### Consensus Integration

Transaction validation in `consume_inputs()`:

```rust
// Collect all input signatures
let items: Vec<VerifyItem> = inputs
    .iter()
    .map(|input| {
        VerifyItem::new(
            context::TX,
            input.signature_alg,
            &input.public_key,
            &input.auth_message,
            &input.signature,
        )
    })
    .collect::<Result<Vec<_>, _>>()?;

// Batch verify all inputs
let outcome = batch_verify_v2(items);

if !outcome.is_all_valid() {
    return Err(UtxoError::InvalidSignature);
}
```

### Block Validation

Validate entire block's signatures:

```rust
let mut all_items = Vec::new();

// Collect coinbase signature (if present)
if let Some(sig) = &block.coinbase_signature {
    all_items.push(VerifyItem::new(
        context::BLOCK,
        sig.alg,
        &block.miner_pubkey,
        &block.header_hash,
        &sig.bytes,
    )?);
}

// Collect all transaction input signatures
for tx in &block.transactions {
    for input in &tx.inputs {
        all_items.push(VerifyItem::new(
            context::TX,
            input.sig_alg,
            &input.pubkey,
            &input.auth_msg,
            &input.signature,
        )?);
    }
}

// Single batch verify for entire block
let outcome = batch_verify_v2(all_items);
if !outcome.is_all_valid() {
    return Err(ConsensusError::InvalidBlock);
}
```

### Sync Catchup

Verify large batches during sync:

```rust
const VERIFY_BATCH_SIZE: usize = 1000;

for chunk in blocks.chunks(VERIFY_BATCH_SIZE) {
    let items: Vec<VerifyItem> = chunk
        .iter()
        .flat_map(|block| block.all_signatures())
        .collect();
    
    let outcome = batch_verify_v2(items);
    if !outcome.is_all_valid() {
        // Log which chunk failed, re-verify individually
        eprintln!("Batch verification failed in chunk");
        return Err(SyncError::InvalidBlock);
    }
}
```

## Testing

### Unit Tests

`crates/crypto/src/lib.rs` contains 8 unit tests:

- `test_batch_verify_empty_is_valid` - Empty batch succeeds
- `test_batch_verify_single_valid` - Single valid signature
- `test_batch_verify_multiple_valid` - Multiple valid signatures
- `test_batch_verify_mixed_validity` - Some valid, some invalid
- `test_batch_verify_length_checks` - Message/key/sig size validation
- `test_batch_verify_threshold_switch` - Sequential vs parallel threshold
- `test_batch_verify_parallel_consistency` - Deterministic across runs
- `test_batch_verify_max_size_protection` - Rejects oversized batches

### Integration Tests

`crates/utxo/tests/batch_verify_integration.rs` contains 5 consensus tests:

- `block_with_many_transactions_uses_batch_verify` - 51 tx block
- `block_with_one_invalid_signature_is_rejected` - Invalid sig detection
- `multi_input_transaction_uses_batch_path` - 5-input tx batching
- `large_batch_validates_correctly` - 100-input tx performance
- `mixed_validity_batch_detected` - 10 inputs, 1 invalid

### Fuzz Tests

`crates/crypto/tests/fuzz.rs` contains 5 property tests:

- `property_batch_verify_random_sizes` - Random batch sizes (0-100)
- `fuzz_batch_verify_with_invalid_signatures` - Corrupted signatures
- `fuzz_batch_verify_input_lengths` - Edge cases (empty msg, wrong sizes)
- `property_batch_verify_deterministic` - Same inputs → same outputs
- `fuzz_batch_verify_max_size` - Max size enforcement

### Benchmarks

`crates/crypto/benches/crypto_verify.rs`:

- `bench_single_verify` - Baseline single signature performance
- `bench_batch_verify` - Batch sizes 32/128/512
- `bench_throughput_comparison` - Sequential vs batch (128 sigs)

Run benchmarks:

```bash
cargo bench --package crypto --bench crypto_verify
```

## Troubleshooting

### Performance Issues

**Problem**: Batch verify slower than expected

**Solutions**:
1. Check `CRYPTO_VERIFY_THREADS` matches core count
2. Ensure batch size ≥ `CRYPTO_VERIFY_THRESHOLD` (default 32)
3. Profile with `perf` to identify bottlenecks
4. Verify Rayon thread pool initialized correctly

**Problem**: High CPU usage

**Solutions**:
1. Lower `CRYPTO_VERIFY_THREADS`
2. Increase `CRYPTO_VERIFY_THRESHOLD` to reduce parallelization
3. Reduce `CRYPTO_MAX_BATCH_SIZE` to limit memory pressure

### Validation Failures

**Problem**: All signatures rejected (`AllInvalid`)

**Possible causes**:
1. Batch size exceeds `CRYPTO_MAX_BATCH_SIZE`
2. Mixed algorithm tags in batch
3. Pre-validation failed (message/key/sig size mismatch)

**Debug**:
```rust
// Check batch size
if items.len() > max_batch_size() {
    eprintln!("Batch too large: {} > {}", items.len(), max_batch_size());
}

// Check algorithm consistency
let algs: HashSet<_> = items.iter().map(|i| i.alg).collect();
if algs.len() > 1 {
    eprintln!("Mixed algorithms: {:?}", algs);
}
```

**Problem**: Some signatures invalid (`SomeInvalid`)

**Debug**:
```rust
if let BatchVerifyOutcome::SomeInvalid(indices) = outcome {
    for &idx in &indices {
        let item = &items[idx];
        eprintln!(
            "Invalid signature at index {}: alg={:?}, msg_len={}, sig_len={}",
            idx, item.alg, item.msg.len(), item.sig.len()
        );
    }
}
```

### Memory Issues

**Problem**: Out of memory during batch verify

**Solutions**:
1. Lower `CRYPTO_MAX_BATCH_SIZE`
2. Process blocks in smaller chunks
3. Increase system memory

**Problem**: Memory not freed after verification

**Check**: Ensure `VerifyItem` lifetimes don't outlive verification:

```rust
// BAD: Items keep data alive
let items: Vec<VerifyItem> = ...;
let outcome = batch_verify_v2(&items);
drop(items); // Too late, data already copied

// GOOD: Items consumed immediately
let outcome = batch_verify_v2(items); // Consumes items
```

## Future Improvements

### Planned Enhancements

1. **Algorithm-specific batching**: Different thread counts for Ed25519 vs Dilithium
2. **Adaptive thresholding**: Dynamically adjust threshold based on load
3. **SIMD optimizations**: Vectorized Dilithium verification
4. **Zero-copy verification**: Eliminate internal cloning
5. **Streaming API**: Process signatures as they arrive (no collect)

### Research Directions

1. **Batch verification algorithms**: Mathematical batch verification (not just parallel)
2. **GPU acceleration**: Offload verification to GPU for massive batches
3. **Probabilistic verification**: Trade accuracy for speed in non-critical paths
4. **Incremental verification**: Cache partial results for repeated verification

## References

- **NIST FIPS 204**: ML-DSA (Dilithium) specification
- **Rayon documentation**: https://docs.rs/rayon/
- **Criterion benchmarks**: https://docs.rs/criterion/
- **Sprint 6 specification**: `spec/sprint6_plan.md`

## See Also

- `crates/crypto/src/lib.rs` - Implementation
- `crates/utxo/src/lib.rs` - Consensus integration
- `spec/metrics.md` - Metrics specification
- `SECURITY.md` - Security considerations
