# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
