# Fuzz Testing for PQ-PRIV Privacy Features

This directory contains fuzz targets for testing the robustness and security of privacy-related cryptographic primitives.

## Overview

Fuzzing is a crucial security testing technique that feeds random/malformed data to functions to discover edge cases, crashes, and potential vulnerabilities. Our fuzz targets cover:

1. **Range Proof Verification** (`fuzz_range_proof`)
   - Tests `verify_range()` with malformed proofs
   - Tests commitment construction edge cases
   - Validates proof size limits (MAX_PROOF_SIZE = 32KB)
   - Explores extreme value ranges (0, u64::MAX, etc.)

2. **Commitment Balance** (`fuzz_commitment_balance`)
   - Tests `balance_commitments()` with random commitment sets
   - Validates inflation protection logic
   - Tests edge cases: empty inputs/outputs, overflow scenarios
   - Explores various input/output count combinations

3. **Malformed Proofs** (`fuzz_malformed_proofs`)
   - Focuses on proof parsing robustness
   - Tests boundary conditions (0 bytes, 32KB, 32KB+1, etc.)
   - Mutation testing: flips bits in valid proofs
   - Tests truncated, extended, and repeated patterns

4. **Confidential Transactions** (`fuzz_confidential_tx`)
   - End-to-end fuzzing of confidential TX validation
   - Tests proof count mismatches
   - Validates DoS protection (MAX_PROOFS_PER_BLOCK)
   - Tests UTXO application pipeline

## Prerequisites

Install `cargo-fuzz`:

```bash
cargo install cargo-fuzz
```

**Note**: Fuzzing requires nightly Rust toolchain:

```bash
rustup install nightly
```

## Running Fuzz Tests

### Quick Test (30 seconds each)

```bash
# From repository root
cd fuzz

cargo +nightly fuzz run fuzz_range_proof -- -max_total_time=30
cargo +nightly fuzz run fuzz_commitment_balance -- -max_total_time=30
cargo +nightly fuzz run fuzz_malformed_proofs -- -max_total_time=30
cargo +nightly fuzz run fuzz_confidential_tx -- -max_total_time=30
```

### Extended Fuzzing (recommended for CI)

```bash
# Run for 5 minutes each
cargo +nightly fuzz run fuzz_range_proof -- -max_total_time=300
cargo +nightly fuzz run fuzz_commitment_balance -- -max_total_time=300
cargo +nightly fuzz run fuzz_malformed_proofs -- -max_total_time=300
cargo +nightly fuzz run fuzz_confidential_tx -- -max_total_time=300
```

### Continuous Fuzzing (until crash or Ctrl+C)

```bash
cargo +nightly fuzz run fuzz_range_proof
```

### Running All Targets

```bash
#!/bin/bash
for target in fuzz_range_proof fuzz_commitment_balance fuzz_malformed_proofs fuzz_confidential_tx; do
    echo "Fuzzing $target..."
    cargo +nightly fuzz run $target -- -max_total_time=60 || echo "$target found issue!"
done
```

## Analyzing Results

### Viewing Coverage

```bash
cargo +nightly fuzz coverage fuzz_range_proof
cargo +nightly cov -- show target/*/release/fuzz_range_proof \
    --format=html \
    --instr-profile=fuzz/coverage/fuzz_range_proof/coverage.profdata \
    > coverage.html
```

### Reproducing Crashes

If fuzzing finds a crash, the input is saved to `fuzz/artifacts/fuzz_<target>/`:

```bash
# Reproduce the crash
cargo +nightly fuzz run fuzz_range_proof fuzz/artifacts/fuzz_range_proof/crash-<hash>

# Debug with verbose output
RUST_BACKTRACE=1 cargo +nightly fuzz run fuzz_range_proof fuzz/artifacts/fuzz_range_proof/crash-<hash>
```

### Minimizing Crash Inputs

```bash
cargo +nightly fuzz tmin fuzz_range_proof fuzz/artifacts/fuzz_range_proof/crash-<hash>
```

## Corpus Management

Fuzz targets build a corpus of interesting inputs over time:

```bash
# View corpus statistics
ls -lh fuzz/corpus/fuzz_range_proof/

# Merge corpora from multiple runs
cargo +nightly fuzz cmin fuzz_range_proof
```

## Integration with CI

Add to `.github/workflows/fuzz.yml`:

```yaml
name: Fuzz Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Nightly at 2 AM
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - name: Fuzz range proofs
        run: cd fuzz && cargo +nightly fuzz run fuzz_range_proof -- -max_total_time=300
      - name: Fuzz commitment balance
        run: cd fuzz && cargo +nightly fuzz run fuzz_commitment_balance -- -max_total_time=300
      - name: Fuzz malformed proofs
        run: cd fuzz && cargo +nightly fuzz run fuzz_malformed_proofs -- -max_total_time=300
      - name: Fuzz confidential TX
        run: cd fuzz && cargo +nightly fuzz run fuzz_confidential_tx -- -max_total_time=300
      - name: Upload artifacts
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts/
```

## Security Considerations

- **No Panics**: All fuzz targets should handle invalid input gracefully without panicking
- **Bounded Resources**: Fuzz targets limit memory usage to avoid OOM (e.g., max 100 commitments)
- **DoS Protection**: Tests validate MAX_PROOF_SIZE and MAX_PROOFS_PER_BLOCK limits
- **Determinism**: Repeated fuzzing runs should be reproducible with same seed

## Expected Behavior

All fuzz targets should complete without crashes. Expected outcomes:

- ✅ Invalid proofs return `false` from `verify_range()`
- ✅ Malformed data returns `Err()` from parsing functions
- ✅ Oversized proofs are rejected (> MAX_PROOF_SIZE)
- ✅ Unbalanced commitments return `false` from `balance_commitments()`
- ✅ Invalid transactions fail validation in `apply_block()`

## Resources

- [cargo-fuzz book](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [AFL fuzzing strategies](https://lcamtuf.coredump.cx/afl/)

## Maintenance

Fuzz targets should be updated when:

- New cryptographic primitives are added
- API signatures change
- New validation rules are implemented
- Security vulnerabilities are discovered

Run fuzzing regularly (at least weekly) to catch regressions early.
