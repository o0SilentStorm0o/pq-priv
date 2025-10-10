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
| `crates/pow`      | Proof-of-Work target/retarget helpers |
| `crates/spec`     | Shared protocol constants/types |
| `crates/tx`       | Transaction model, builder, canonical txid/sighash |
| `crates/utxo`     | In-memory ledger, double-spend detection, integration tests |
| `crates/wallet`   | CLI wallet prototype (key management, audit stubs) |
| `spec/`           | RFC-style protocol & operations documentation |
| `docker/`         | Multi-stage Dockerfile for reproducible builds |
| `scripts/`        | Utility scripts (testnet, checksum writer) |

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

* Všechny buildy a testy spouštějte s `--locked` (Makefile to již nastavuje).
* Linty a testy běží automaticky v GitHub Actions (`.github/workflows/ci.yml`).
* Pro rychlý lokální testnet spusťte `make testnet-up` (ukončení `make testnet-down`).

```bash
BLOCKS=256 make testnet-up
tail -f .testnet/node.log
```

## Docker image

```bash
make docker-build
docker run --rm pqpriv:dev --help
```

For a two-node sandbox with persistent volumes and health-checked RPC services:

```bash
make docker-build
docker compose -f docker/docker-compose.yml up
```

## Dokumentace

* [Implementační blueprint (v0.9)](./spec/blueprint.md) – strategický plán MVP.
* [`spec/build.md`](./spec/build.md) – build & release handbook.
* [`spec/README.md`](./spec/README.md) – struktura specifikací.

Příspěvky jsou vítány! Nezapomeňte si přečíst [CONTRIBUTING.md](./CONTRIBUTING.md) a [SECURITY.md](./SECURITY.md).
