# Sprint 3 Verification

This note captures the manual verification of the Sprint 3 acceptance scope against the current `feature/sprint3` codebase. Each section references the primary implementation surface or tests that satisfy the requirement set.

## 1. Persistence & Storage Schema
- `crates/storage/src/schema.rs` declares the `HEADERS`, `BLOCKS`, `UTXO`, `LINKTAG`, and `META` column families with prefixed keys, matching the spec storage layout.
- `Store::begin_block_batch` and `BlockBatch::commit` in `crates/storage/src/store.rs` and `crates/storage/src/batch.rs` stage headers, block bodies, UTXO/link-tag mutations, and tip metadata into a RocksDB write batch with WAL enabled for atomic commits.
- `CheckpointManager::maybe_snapshot` in `crates/storage/src/checkpoint.rs` drives snapshot creation and retention using the configured interval and keep-count.

## 2. Fork-Choice & Reorg Handling
- `ChainState` in `crates/node/src/state.rs` maintains an index of blocks with cumulative work, selects the heavier branch, and executes `perform_reorg` to undo/redo UTXO state while logging the reorg summary.
- Confirmed transactions are removed from the mempool via `remove_confirmed`, and detached block transactions are reintroduced in canonical order with orphan handling.

## 3. Headers→Blocks Sync & Orphan Management
- `Relay` and `SyncManager` in `crates/node/src/relay.rs` and `crates/node/src/sync.rs` request block bodies for announced headers, track pending hashes, and manage an orphan pool with TTL/limit enforcement.
- `run_peer_event_loop`, `run_chain_event_loop`, and `run_block_sync_task` in `crates/node/src/tasks.rs` wire peer/network events into sync, advertise locators, and update peer best-heights through `NetworkHandle`.

## 4. Mempool Hygiene & Fee Policy
- `TxPool` in `crates/node/src/mempool.rs` enforces byte/orphan caps, min relay fee per vbyte, duplicate link-tag prevention, LRU-style eviction, orphan promotion, and exposes pool statistics for metrics.
- Chain-state integrates the mempool to remove confirmed txs on block application and restore orphaned txs after reorgs.

## 5. Metrics, RPC, and Node Services
- `NodeConfig::load` in `crates/node/src/cfg.rs` surfaces disk paths, snapshot cadence, mempool caps, and sync orphan controls via TOML overrides.
- The async entrypoint in `crates/node/src/main.rs` boots RocksDB, configures snapshots, starts P2P, RPC (with `/metrics`), and the background sync tasks, shutting down gracefully on CTRL-C.
- `RpcContext::render_metrics` in `crates/node/src/rpc.rs` exports Prometheus gauges for peers, tip height, cumulative work, target, mempool utilisation, orphan count, compactions, reorgs, and batch timings, alongside JSON-RPC helpers.

## 6. Documentation, Docker, and Specifications
- `README.md` documents the architecture and Docker sandbox while `spec/storage.md`, `spec/fork-choice.md`, and `spec/metrics.md` describe persistence, fork-choice, sync, and metrics behaviour introduced in Sprint 3.
- `docker/docker-compose.yml` provisions per-node volumes, a two-node topology, and health checks hitting the RPC service.
- `CHANGELOG.md` includes the Sprint 3 release notes covering persistence, sync, mempool hygiene, and metrics.

## 7. Testing & Quality Gates
- Unit coverage spans storage batching/snapshots, consensus cumulative-work helpers, chainstate fork-choice/mempool hygiene, and mempool fee/eviction policies.
- Integration tests in `crates/node/tests/integration.rs` exercise header→block sync, cross-peer reorgs, persistence restart, metrics exposure, and invalid handshakes.
- Linting (`cargo clippy -D warnings`) and dependency policies (`cargo deny`, `cargo audit`) are wired via `deny.toml`, with audits failing only when advisory downloads are unavailable in CI-sandboxed environments.

