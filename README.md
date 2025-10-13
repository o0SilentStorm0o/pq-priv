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
| `crates/rocksdb_stub` | Development stub for RocksDB (fast compilation, no persistence) |
| `crates/spec`     | Shared protocol constants/types |
| `crates/storage`  | RocksDB persistence layer with checkpoint support |
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

## Documentation

* [Implementation blueprint (v0.9)](./spec/blueprint.md) – strategic MVP plan.
* [`spec/build.md`](./spec/build.md) – build & release handbook.
* [`spec/README.md`](./spec/README.md) – specifications structure.

Contributions are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) and [SECURITY.md](./SECURITY.md).
