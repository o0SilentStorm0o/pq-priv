# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Sprint 8: Privacy Phase 1 (Confidential Transactions)

- **Confidential Transactions** using Pedersen commitments to hide transaction amounts
  - Homomorphic commitment scheme: `C(v, r) = v·G + r·H` (128-bit security)
  - Transparent outputs (`value` set, `commitment` None) and confidential outputs (`commitment` set, `value` 0) coexist
  - Mixed transactions supported with secure balance verification
- **Bulletproofs** zero-knowledge range proofs for 64-bit values
  - Proof size: ~672 bytes per proof (logarithmic in range size)
  - Proves value ∈ [0, 2^64-1] without revealing actual value
  - Soundness: <2^-128 probability of forging valid proof for out-of-range value
  - Zero-knowledge: Verifier learns nothing except range validity
- **Commitment Balance Verification** to prevent inflation attacks
  - Homomorphic property: `Σ input_commits = Σ output_commits` (no value created)
  - Enforced for all transactions with ≥1 confidential input/output
  - `verify_commitment_balance()` validates equality without knowing values
- **DoS Protection** with strict validation limits
  - `MAX_PROOF_SIZE = 32 KB` - Individual range proof size limit
  - `MAX_PROOFS_PER_BLOCK = 1000` - Maximum proofs per block (prevents >30s validation)
  - Proofs exceeding limits are rejected at consensus layer
- **Privacy Metrics** exported via Prometheus `/metrics` endpoint
  - `privacy_range_proof_verify_duration_seconds` - Verification latency histogram (p50/p90/p99)
  - `privacy_range_proof_verify_failures_total` - Invalid proof counter
  - `privacy_commitment_balance_verify_duration_seconds` - Balance check latency histogram
  - `privacy_commitment_balance_verify_failures_total` - Balance mismatch counter
- **Comprehensive Testing** with 39 deterministic tests + 4 fuzz targets
  - 22 crypto unit tests (commitments, proofs, balance verification, security edge cases)
  - 9 TX integration tests (output creation, serialization, end-to-end flow)
  - 8 consensus tests (validation rules, rejection scenarios, DoS protection)
  - 4 fuzz targets with 25+ strategies (proof robustness, commitment arithmetic, serialization)
- **Complete Documentation** (823 lines in `docs/privacy.md`)
  - Cryptographic primitives, security model, transaction model, consensus rules
  - API usage guide, performance benchmarks, testing guide, migration guide
  - Security considerations, future roadmap (Phase 2/3), troubleshooting appendix

### Performance - Sprint 8: Privacy Phase 1

- **Proof Generation**: ~24ms average (24ms p50, 50ms p99) for 64-bit range
- **Proof Verification**: ~15ms average (15ms p50, 20ms p99) per proof
- **Block Validation**: ~15 seconds for 1000 proofs (target: <30s at MAX_PROOFS_PER_BLOCK)
- **Commitment Operations**: <50µs per commit_value/verify_commitment
- **Storage Overhead**: ~3.7x per confidential output vs transparent (672-byte proof + 32-byte commitment)
- **Memory Usage**: ~2-4 MB for batch proof verification (transient, freed after validation)

### Security - Sprint 8: Privacy Phase 1

- **Cryptographic Strength**: 128-bit security against discrete logarithm attacks (Curve25519)
- **Soundness**: <2^-128 probability of forging valid range proof for invalid value
- **Zero-Knowledge**: Verifier learns nothing except that value ∈ [0, 2^64-1]
- **Inflation Protection**: Commitment balance verification prevents value creation/destruction
- **DoS Resistance**: MAX_PROOF_SIZE (32KB) and MAX_PROOFS_PER_BLOCK (1000) prevent resource exhaustion
- ⚠️ **Not Quantum-Resistant**: Current Pedersen commitments vulnerable to Shor's algorithm (requires lattice-based commitments in Phase 2)

### Breaking Changes - Sprint 8: Privacy Phase 1

- **Transaction validation**: Transactions with `value > 0` AND `commitment != None` are now rejected (must be either transparent OR confidential)
- **Witness requirement**: Confidential outputs require corresponding range proofs in transaction witness
- **Consensus rules**: 
  - Range proofs exceeding `MAX_PROOF_SIZE = 32 KB` are rejected
  - Blocks with `>MAX_PROOFS_PER_BLOCK = 1000` total range proofs are rejected
  - Transactions with ≥1 confidential input/output must satisfy commitment balance equation
- **RPC metrics**: New Prometheus metrics require `/metrics` endpoint to be enabled

### Added - Sprint 6: Batch Signature Verification

- **High-performance batch verification API** (`batch_verify_v2()`) with 6-8x speedup
  - Parallel verification using Rayon thread pool
  - Automatic threshold switching (sequential < 32 signatures, parallel ≥ 32)
  - Runtime-configurable via `CRYPTO_VERIFY_THREADS`, `CRYPTO_VERIFY_THRESHOLD`, `CRYPTO_MAX_BATCH_SIZE`
  - Integrated into consensus validation (`consume_inputs()` in UTXO crate)
- **Prometheus metrics for signature verification**
  - `batch_verify_calls_total` - Total batch_verify_v2() invocations
  - `batch_verify_items_total` - Total signatures processed
  - `batch_verify_invalid_total` - Invalid signatures detected
  - `batch_verify_duration_us_total` - Cumulative verification time
  - Exportable via `/metrics` endpoint in node crate
- **Comprehensive documentation** (`docs/crypto/batch-verify.md`)
  - API reference, configuration guide, benchmark results
  - Security considerations (domain separation, zeroization)
  - Usage patterns, troubleshooting, testing guide
- **Security hardening**
  - Extended zeroization to CBOR buffers in `domain_separated_hash()`
  - All sensitive message data automatically cleared from memory
- **Test coverage** (128 workspace tests)
  - 8 unit tests (empty batch, mixed validity, threshold switching, max size protection)
  - 5 integration tests (consensus-level validation, multi-input tx, large batches)
  - 5 fuzz/property tests (random sizes, corrupted signatures, determinism)
- **Performance benchmarks** (Criterion)
  - Single verify baseline: 111 µs per signature (9 Kelem/s)
  - Batch verify/32: 18.3 µs per signature → **6.1x speedup** (54 Kelem/s)
  - Batch verify/128: 15.5 µs per signature → **7.2x speedup** (65 Kelem/s)
  - Batch verify/512: 13.8 µs per signature → **8.0x speedup** (73 Kelem/s)
  - Exceeds 2-5x target for typical block validation scenarios

### Added
- Complete RPC server with `/health`, `/chain/tip`, and `/metrics` endpoints
- Development mining endpoint `/dev/mine` (feature-gated behind `devnet`)
- Comprehensive PowerShell testnet integration script (`scripts/testnet-up.ps1`)
- Docker Compose multi-node testnet configuration
- Dynamic difficulty adjustment in mining endpoints
- **E2E multi-node test suite** with 3 topologies: line, star, partition (PR #XX)
  - Automated test scripts (`e2e-test.ps1`, `mine-blocks.ps1`, `collect-logs.ps1`)
  - Deterministic genesis for reproducible testing (`E2E_FIXED_GENESIS=1`)
  - Fixed IP addressing and P2P seed configuration for all topologies
  - Comprehensive test artifacts (JSON reports, Docker logs)
- **P2P scaling documentation** (`docs/p2p-scaling-strategy.md`)
  - Current capacity analysis (100 peers, 2048-message buffer)
  - Roadmap to mainnet scale (1000+ peers)
  - Three optimization strategies identified with implementation estimates

### Fixed
- Axum 0.7 migration: corrected `Arc<Mutex<T>>` access patterns in RPC handlers
- Fixed `spawn_rpc_server` signature to return bound socket address
- Mining timestamp and difficulty calculation for multi-block mining
- **Critical: Fork-choice bug in network partition scenarios** (PR #XX)
  - Root cause: `apply_block()` validated difficulty against wrong chain history
  - Impact: Bridge node rejected longer chain blocks with `InvalidBits` error
  - Solution: Skip difficulty/timestamp validation for side chain blocks
  - Validation now only applies when blocks extend active tip
  - Tested: 250-block partition with successful reorg
- **Critical: Event channel overflow under large sync bursts** (PR #XX)
  - Root cause: `EVENT_CHANNEL_SIZE=128` too small for 200+ block syncs
  - Symptom: "peer event loop lagged" warnings, sync stalled at height 1
  - Solution: Increased channel size to 2048 (16× capacity)
  - Tested: 250-block sync with zero lag warnings

### Changed
- Upgraded to Axum 0.7.9 with proper shared state handling
- Improved testnet scripts with Windows PowerShell compatibility
- Enhanced Docker healthchecks and volume management
- **P2P event system capacity** increased from 128 to 2048 messages
  - Sufficient for ~100 concurrent peers under burst conditions
  - Handles competing chain syncs (200-250 blocks) without message loss

## [0.1.0] - 2025-10-14

### Added
- Sprint 0: reproducible builds, CI matrix, Docker image, testnet scripts and repository templates
- Sprint 1: basic P2P network, mempool, JSON-RPC and new security tools in CI
- Sprint 3: persistent RocksDB storage, fully integrated sync pipeline,
  mempool hygiene during reorgs and Prometheus metrics in RPC server
