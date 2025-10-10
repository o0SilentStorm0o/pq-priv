# Sprint 3 Scope Breakdown

This document enumerates the outstanding work described in the sprint checklist and breaks it into smaller chunks that can be tackled individually. Each chunk is sized to be feasible within a single assistant session.

## 1. P2P ↔ Sync Wiring
- **Task A:** Implement a runtime task that subscribes to `NetworkHandle` peer events and dispatches inbound `NetMessage` inventory, header, and block messages to `SyncManager`.
- **Task B:** Integrate `SyncManager::register_headers` with chain notifications so that new local tips are registered for peers.
- **Task C:** Ensure peer best-height tracking is updated via `NetworkHandle::update_best_height` when new heights are observed.

## 2. Block Application ↔ Mempool Hygiene
- **Task D:** Wire `ChainState::apply_block` to call `TxPool::remove_confirmed` for transactions included in confirmed blocks.
- **Task E:** Extend reorg handling so that transactions from orphaned blocks are re-added to the mempool in canonical order.
- **Task F:** Add tests covering confirmed transaction removal and reorg reinsertion logic.

## 3. Node Bootstrap / Services
- **Task G:** Replace the demo `run_node` loop with an async main that loads configuration, opens the database, and constructs `SyncManager`, `TxPool`, and `Relay`.
- **Task H:** Launch background services (P2P network, RPC server with `/metrics`, block sync task) from the new runtime entry point.
- **Task I:** Configure snapshots via `configure_snapshots` using values from `NodeConfig` instead of hard-coded defaults.

## 4. Documentation & Config Updates
- **Task J:** Update documentation (`README.md`, `spec/storage.md`, `spec/fork-choice.md`) with RocksDB schema, reorg algorithm, and sync pipeline details.
- **Task K:** Author a new `spec/metrics.md` describing Prometheus metrics exposed by the node.
- **Task L:** Add a "Sprint 3" entry to `CHANGELOG.md` summarizing persistence, sync, mempool, and metrics work.
- **Task M:** Update `docker/docker-compose.yml` to include per-node volumes, a two-node topology, and the RPC health check.

## 5. Testing & Automation
- **Task N:** Implement integration tests for header-to-block sync between two nodes, end-to-end reorg handling, persistent restart, and P2P ban-score behavior.
- **Task O:** Add automated verification for the `/metrics` endpoint (integration test or smoke test).
- **Task P:** Ensure the new `crates/storage` crate is tracked in Git and incorporated into CI workflows.

## 6. Quality Gates & Tooling
- **Task Q:** Run `cargo clippy --deny warnings` across the workspace and address any findings.
- **Task R:** Run `cargo deny` and `cargo audit`, resolving outstanding issues.
- **Task S:** Update CI configurations to include linting and audit steps if they are not already enforced.

Each task can be scheduled as a separate assistant session. When tackling an individual task, reference this breakdown to ensure coverage of the original Sprint 3 acceptance criteria.
