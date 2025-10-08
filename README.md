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
| `crates/node`     | Full node daemon: CLI entrypoint, mining loop, future P2P/RPC |
| `crates/pow`      | Proof-of-Work target/retarget helpers |
| `crates/spec`     | Shared protocol constants/types |
| `crates/tx`       | Transaction model, builder, canonical txid/sighash |
| `crates/utxo`     | In-memory ledger, double-spend detection, integration tests |
| `crates/wallet`   | CLI wallet prototype (key management, audit stubs) |
| `spec/`           | RFC-style protocol & operations documentation |
| `docker/`         | Multi-stage Dockerfile for reproducible builds |
| `scripts/`        | Utility scripts (testnet, checksum writer) |

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

## Dokumentace

* [Implementační blueprint (v0.9)](./spec/blueprint.md) – strategický plán MVP.
* [`spec/build.md`](./spec/build.md) – build & release handbook.
* [`spec/README.md`](./spec/README.md) – struktura specifikací.

Příspěvky jsou vítány! Nezapomeňte si přečíst [CONTRIBUTING.md](./CONTRIBUTING.md) a [SECURITY.md](./SECURITY.md).
