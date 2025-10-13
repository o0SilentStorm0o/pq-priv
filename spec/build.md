# Build & Release Handbook

This document describes procedures for deterministic builds, CI pipelines and publication of binary artifacts for PQ-PRIV. It follows the implementation blueprint and is binding for all official releases.

## Toolchain

* **Rust**: 1.90.0 (edition 2024). Toolchain is locked in `rust-toolchain.toml`.
* **Cargo**: use `--locked` to respect `Cargo.lock`.
* **C compilers / linkers**: Docker image installs `clang`, `pkg-config`, `libssl-dev`.

## Reproducible builds

1. Clean previous outputs: `rm -rf target/ dist/`.
2. Run `make build-release`. Makefile sets `codegen-units=1`, `thin LTO`, symbol `strip` and `-C link-arg=-s`.
3. Copy resulting binaries `target/release/node` and `target/release/wallet` to `dist/` as `pqprivd` and `pqpriv-wallet`.
4. Generate `SHA256SUMS`:

```bash
python scripts/write_sha256.py dist/
```

5. Sign the `SHA256SUMS` file using release key (GPG/hardware HSM) and publish together with binaries.

## CI pipelines

### `.github/workflows/ci.yml`

* Runs on push, pull request and manually.
* Matrix for `ubuntu-latest`, `macos-latest`, `windows-latest`.
* Steps: `cargo fmt --check`, `cargo clippy`, `cargo test`, `cargo deny`, `cargo audit`.
* Security checks (`deny`/`audit`) run on linux runner.

### `.github/workflows/release.yml`

* Runs on tag `v*` or manually.
* Creates artifacts for linux/macos/windows, renames binaries to `pqprivd` and `pqpriv-wallet`.
* Writes `SHA256SUMS` within workflow and uploads artifacts.

## Docker image

* `docker/Dockerfile` is multi-stage:
  * **builder**: `rust:1.90-bullseye`, installs build dependencies and compiles binaries.
  * **runtime**: `debian:bookworm-slim`, creates unprivileged user `pqpriv` and installs binaries.
* Local build: `make docker-build`.
* Run test instance:

```bash
docker run --rm pqpriv:dev --help
```

## Testnet scripts

* `scripts/testnet-up.sh` launches a local testnet (`node run`) using a generated config under `.testnet/`, exercises the RPC health/chain endpoints, mines a dev block, and then verifies persistence after restart.
* `scripts/testnet-down.sh` safely terminates running `target/release/node` processes.

## Release checklist

1. All tests and lints passing (`make lint`, `make test`, `make audit`).
2. Updated specifications (`/spec`), changelog, ADR.
3. `make build-release` + `SHA256SUMS`.
4. Signed artifacts uploaded via `release.yml`.
5. Published security advisory if release contains security fixes.

Following this procedure is essential for auditable and secure network operation.
