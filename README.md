# PQ-PRIV

**PQ-PRIV (Post-Quantum Privacy Layer-1)** is a research blockchain designed from day one to combine:

- 🧩 **Post-quantum cryptography** (CRYSTALS-Dilithium + STARK proofs)
- 🕵️ **Strong privacy by default** (stealth addresses, confidential amounts)
- ⚖️ **Compliance-ready UX** (selective disclosure, exchange subaddresses)
- 🧠 **Built in Rust**, hybrid PoW/PoS consensus, and future-proof crypto-agility.

---

## Project Structure

| Path | Description |
|------|-------------|
| `crates/codec`    | Binary serialization helpers (CBOR-style, varint, checksums) |
| `crates/consensus`| Block/chain rules, PoW utilities, validation scaffolding |
| `crates/crypto`   | PQ primitives (Dilithium scaffolding, commitments, hashing) |
| `crates/node`     | Full node daemon: async runtime, P2P/RPC services, sync orchestration |
| `crates/p2p`      | P2P networking: peer management, handshake, inventory system |
| `crates/pow`      | Proof-of-Work target/retarget helpers |
| `crates/spec`     | Shared protocol constants/types |
| `crates/storage`  | RocksDB persistence layer with tunable performance and checkpoint support |
| `crates/tx`       | Transaction model, builder, canonical txid/sighash |
| `crates/utxo`     | In-memory ledger, double-spend detection, integration tests |
| `crates/wallet`   | CLI wallet prototype (key management, audit stubs) |
| `spec/`           | RFC-style protocol & operations documentation |
| `docker/`         | Multi-stage Dockerfile for reproducible builds |
| `scripts/`        | Utility scripts (PowerShell/bash testnet, checksum writer) |

---

---

## Node architecture highlights

PQ-PRIV's full node couples persistent state, fork choice, and the sync pipeline to
match the Sprint 3 acceptance criteria:

- **RocksDB persistence** – Blocks, headers, UTXOs, and link tags are stored in
  dedicated column families with typed key prefixes. Tip metadata, compact UTXO
  indices, and snapshot checkpoints live in the meta column family. See
  [`spec/storage.md`](./spec/storage.md) for an exhaustive layout reference.
- **Deterministic fork choice** – Chainstate tracks an in-memory block index with
  cumulative work accounting, reorg detection, and broadcast tip updates. The
  reorg path unwinds/rewinds UTXO state, persists the new tip, snapshots when
  configured, and keeps the mempool consistent. Details are captured in
  [`spec/fork-choice.md`](./spec/fork-choice.md).
- **Sync pipeline** – The runtime launches dedicated tasks for peer events,
  chain notifications, and locator broadcasting. `SyncManager` consumes network
  inventories to drive header registration and block downloads while updating
  peer best heights. The end-to-end flow is documented in
  [`spec/fork-choice.md`](./spec/fork-choice.md) and [`spec/metrics.md`](./spec/metrics.md).
- **Prometheus metrics** – `/metrics` exposes chain height, cumulative work,
  mempool depth, reorg counters, and RocksDB compaction gauges for monitoring.

> ⚠️ **Security Warning**: The `/metrics` endpoint is **NOT intended for public internet exposure**.
> It should be bound to `localhost` (default: `127.0.0.1:8645`) or protected with authentication
> (mTLS, reverse proxy with basic auth). Database size and performance metrics can leak information
> about blockchain activity and system capacity. See [`docs/perf/storage.md`](./docs/perf/storage.md#metrics-security)
> for configuration examples.

---

## Development

```bash
# Install the pinned toolchain
rustup toolchain install 1.90.0
rustup component add rustfmt clippy

# Run the standard quality gates
make fmt
make lint
make test
make audit
```

* All builds and tests run with `--locked` (Makefile sets this by default)
* Lints and tests run automatically in GitHub Actions (`.github/workflows/ci.yml`)
* For a quick local testnet, run the PowerShell script (Windows) or bash script (Linux/macOS)

### Local Testnet (Windows)

```powershell
# PowerShell 7+ required
.\scripts\testnet-up.ps1
```

The script:
- Builds the node with `devnet` feature (enables `/dev/mine` endpoint)
- Generates configuration in `.testnet/node.toml`
- Starts the node with automatic port allocation
- Runs 12 comprehensive integration tests:
  - Health checks, genesis verification, mining (6 blocks)
  - Metrics validation, snapshot creation, restart persistence
  - Database integrity, error handling
- Cleans up: stops node, removes test database

### Docker Multi-Node Testnet

```bash
make docker-build
docker compose -f docker/docker-compose.yml up
```

This starts:
- **node_a**: RPC on `:8645`, P2P on `:8644`
- **node_b**: RPC on `:8745`, P2P on `:8744`
- Health checks every 15 seconds
- Persistent volumes for blockchain data and snapshots

Test the nodes:
```bash
curl http://localhost:8645/health      # node_a
curl http://localhost:8745/health      # node_b
curl http://localhost:8645/chain/tip   # genesis block
```

## E2E Multi-Node Testing

Comprehensive Docker-based test suite for validating P2P networking and consensus:

```bash
# Test linear topology (A → B → C sync)
./scripts/e2e-test.ps1 -topology line -ports 8545,8546,8547 -minHeight 101

# Test star topology (hub + 3 leafs)
./scripts/e2e-test.ps1 -topology star -ports 8550,8551,8552,8553 -minHeight 100

# Test partition + reorg (competing chains)
./scripts/e2e-test.ps1 -topology partition -ports 8560,8561,8562 -minHeight 250
```

**Validated Scenarios:**
- ✅ 10-node concurrent mining and sync
- ✅ Network partition with successful reorg (250-block chains)
- ✅ Fork-choice algorithm selecting longest chain
- ✅ Zero event lag under burst conditions

For detailed test scenarios and capacity analysis:
📖 **[E2E Testing Guide](./docker/e2e/README.md)**

## Network Scalability

**Current Capacity (MVP/Testnet):**
- Tested: 10 concurrent nodes, 250-block burst syncs
- Safe capacity: ~100 concurrent peers
- Event buffer: 2048 messages (sufficient for testnet scale)

**Roadmap to Mainnet (1000+ peers):**
- Phase 2 (6mo): Public testnet with monitoring
- Phase 3 (12mo): Optimize based on metrics (deduplication, segmented channels)
- Phase 4 (24mo): Actor-based architecture for production scale

For scaling strategy and future optimizations:
📖 **[P2P Scaling Strategy](./docs/p2p-scaling-strategy.md)**

## Documentation

* [Implementation blueprint (v0.9)](./spec/blueprint.md) – strategic MVP plan.
* [`spec/build.md`](./spec/build.md) – build & release handbook.
* [`spec/README.md`](./spec/README.md) – specifications structure.
* **[Cryptography Runtime Analysis](./docs/crypto/runtime-sizes.md)** – Memory footprint, CBOR canonicity, and performance analysis for post-quantum signatures.
* **[Storage Performance Tuning](./docs/perf/storage.md)** – RocksDB configuration and optimization guide.
* **[P2P Scaling Strategy](./docs/p2p-scaling-strategy.md)** – Network capacity and mainnet roadmap.
* **[E2E Testing Guide](./docker/e2e/README.md)** – Multi-node test scenarios and validation.
* **[Snapshot and Restore Guide](./docs/snapshots.md)** – Database backup/restore with security hardening.

Contributions are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) and [SECURITY.md](./SECURITY.md).
