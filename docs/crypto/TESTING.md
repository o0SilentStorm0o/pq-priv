# Sprint 5 Cryptography Integration Testing

This directory contains comprehensive integration tests for the Dilithium2 post-quantum signature implementation.

## Test Levels

### 1. Unit Tests (crypto crate)
**Location**: `crates/crypto/tests/integration.rs`

**Coverage**:
- End-to-end workflow (keygen → sign → verify)
- Cross-algorithm compatibility (Ed25519 ↔ Dilithium2)
- Trait implementation verification
- Multiple signatures (randomness check)
- Corruption detection (signature + public key)
- Key derivation determinism
- Large message handling (0 bytes to 1 MB)
- Unsupported algorithm rejection
- Serialization/deserialization
- Throughput benchmarking (100 operations)

**Run**:
```powershell
cargo test -p crypto --test integration -- --nocapture
```

**Expected Output**:
```
running 10 tests
test dilithium2_end_to_end_workflow ... ok
test cross_algorithm_compatibility ... ok
test dilithium2_trait_implementation ... ok
test dilithium2_multiple_signatures ... ok
test dilithium2_corruption_detection ... ok
test key_derivation_is_deterministic ... ok
test dilithium2_large_message ... ok
test unsupported_algorithms_rejected ... ok
test signature_serialization ... ok
test dilithium2_throughput_test ... ok

=== Dilithium2 Throughput Test ===
Signed 100 messages in ~120ms
Average signing time: ~1.2ms
Verified 100 signatures in ~26ms
Average verification time: ~260µs
```

---

### 2. Transaction Tests (tx crate)
**Location**: `crates/tx/tests/integration.rs`

**Coverage**:
- Transaction input signing with Dilithium2
- Complete multi-input/multi-output transactions
- Mixed algorithm transactions (Ed25519 + Dilithium2)
- Transaction serialization (CBOR)
- Stress test (50 transactions with verification)

**Run**:
```powershell
cargo test -p tx --test integration -- --nocapture
```

**Expected Output**:
```
running 5 tests
test sign_transaction_input_with_dilithium2 ... ok
test complete_transaction_workflow ... ok
test transaction_with_mixed_algorithms ... ok
test transaction_serialization ... ok
test stress_test_multiple_transactions ... ok

Verified 50 transactions in ~14ms
Average per transaction: ~280µs
```

---

### 3. Docker E2E Tests (Optional)
**Location**: `docker/e2e/crypto-test.yml`

**Coverage**:
- Multi-node network with Dilithium2 signatures
- Cross-node transaction propagation
- Full blockchain validation

**Run**:
```powershell
.\scripts\crypto-e2e-test.ps1
```

**Steps**:
1. Builds Docker images with crypto code
2. Starts 2 nodes (A and B) with Dilithium2
3. Runs all crypto + tx integration tests
4. Cleans up containers

**Note**: Requires Docker Desktop running.

---

## Test Metrics

### Performance Benchmarks (Reference Implementation)

| Operation | Time (avg) | Throughput |
|-----------|------------|------------|
| Dilithium2 Sign | 1.2 ms | 833 ops/sec |
| Dilithium2 Verify | 0.26 ms | 3,846 ops/sec |
| Ed25519 Sign | 0.03 ms | 33,333 ops/sec |
| Ed25519 Verify | 0.08 ms | 12,500 ops/sec |

**Slowdown Factor**: ~40x for signing, ~3x for verification

### Key Sizes

| Algorithm | Public Key | Secret Key | Signature |
|-----------|------------|------------|-----------|
| Ed25519 | 32 B | 32 B | 64 B |
| Dilithium2 | 1,312 B | 2,560 B | 2,420 B |

**Size Factor**: ~41x for public keys, ~80x for secret keys, ~38x for signatures

### Test Coverage

| Test Suite | Tests | Lines | Coverage |
|------------|-------|-------|----------|
| crypto integration | 10 | 350+ | Core crypto API |
| tx integration | 5 | 280+ | Transaction signing |
| **Total** | **15** | **630+** | **End-to-end** |

---

## Known Limitations

1. **Non-deterministic keygen**: `pqcrypto-dilithium` uses system entropy, not seeded RNG
   - **Impact**: Keys from same seed may differ across runs
   - **Mitigation**: Planned migration to `liboqs` in future sprint

2. **Reference implementation**: Not optimized with AVX2/AVX-512
   - **Impact**: ~3x slower than optimized version
   - **Mitigation**: Acceptable for initial deployment, optimize later

3. **No batch verification**: Each signature verified independently
   - **Impact**: Block validation time scales linearly with TX count
   - **Mitigation**: Planned for future (batch verification API)

---

## Troubleshooting

### Test Failures

**"InvalidKey" error**:
- Ensure using Dilithium2-sized keys (not Ed25519)
- Check that `dev_stub_signing` feature matches test expectations

**Timeout in throughput tests**:
- Normal on slow hardware (reference implementation is unoptimized)
- Increase timeout threshold if needed

**Docker tests fail**:
- Ensure Docker Desktop is running
- Check port availability (8545, 8546, 9000, 9001)
- Try `docker system prune -a` if build cache is stale

### Performance Issues

If signing/verification is unexpectedly slow:
1. Check CPU load (other processes)
2. Run in `--release` mode (10x faster)
3. Disable debug logging (`RUST_LOG=error`)

---

## Next Steps

After Sprint 5:
- [ ] Integrate with consensus (block signature validation)
- [ ] Add wallet CLI support (`keygen --scheme dilithium`)
- [ ] Performance profiling (flamegraphs)
- [ ] Consider `liboqs` migration for optimization
- [ ] Implement batch verification

---

## References

- [NIST FIPS 204: Dilithium Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [pqcrypto-dilithium Crate](https://crates.io/crates/pqcrypto-dilithium)
- [PQClean Project](https://github.com/PQClean/PQClean)
