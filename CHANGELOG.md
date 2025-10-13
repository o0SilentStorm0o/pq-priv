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

### Fixed
- Axum 0.7 migration: corrected `Arc<Mutex<T>>` access patterns in RPC handlers
- Fixed `spawn_rpc_server` signature to return bound socket address
- Mining timestamp and difficulty calculation for multi-block mining

### Changed
- Upgraded to Axum 0.7.9 with proper shared state handling
- Improved testnet scripts with Windows PowerShell compatibility
- Enhanced Docker healthchecks and volume management

## [0.1.0] - 2025-10-14

### Added
- Sprint 0: reproducible builds, CI matrix, Docker image, testnet scripts and repository templates
- Sprint 1: basic P2P network, mempool, JSON-RPC and new security tools in CI
- Sprint 3: persistent RocksDB storage, fully integrated sync pipeline,
  mempool hygiene during reorgs and Prometheus metrics in RPC server
