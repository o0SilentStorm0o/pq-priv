# Contributing to PQ-PRIV

Thank you for wanting to help with the implementation of the post-quantum privacy network PQ-PRIV. This document summarizes the minimum requirements for the development environment, the review process and security principles.

## Required toolchain and MSRV

* **MSRV (minimum supported Rust version):** `1.90.0`.
* Toolchain is locked in the [`rust-toolchain.toml`](./rust-toolchain.toml) file. Please do not change it without coordinating with the core team.
* If the version needs to be upgraded:
  1. Open an RFC/issue with justification (security fix, need for 2024 edition, etc.).
  2. Update `RUST_TOOLCHAIN.txt`, `rust-toolchain.toml`, CI workflow and documentation.
  3. Verify that `cargo build --locked` and `cargo test --locked` pass on both old and new toolchain.
  4. Inform the community in release notes.

## Local development

```bash
# toolchain (Rust 1.90+ with edition 2024 support)
rustup default stable
rustup component add clippy rustfmt

# complete set of checks
make fmt
make lint
make test
make audit
```

* If you don't have `cargo-deny` and `cargo-audit` yet, install them using `cargo install cargo-deny cargo-audit`.
* Use all commands with the `--locked` flag to keep builds deterministic.
* In critical paths (cryptography, consensus) avoid `unwrap()`/`expect()` – prefer propagating errors.
* Follow workspace structure according to blueprint and respect `alg_tag` crypto-agility.

## Required checks

All pull requests must pass the following steps in CI. Before submitting a PR, run equivalent commands locally:

* `cargo fmt --all -- --check`
* `cargo clippy --workspace --all-targets --all-features -- -D warnings`
* `cargo test --workspace --all-targets --locked`
* `cargo deny check`
* `cargo audit --deny warnings`

These checks are set as "required" for merge into protected branches.

## Reproducible builds

* Run release compilation via `make build-release`, which sets consistent `RUSTFLAGS` and `release` profile (`codegen-units=1`, `thin LTO`, `strip` symbols).
* For auditability, store artifacts and checksums (`SHA256SUMS`).
* Docker image can be created using `make docker-build`; multi-stage Dockerfile minimizes runtime image.

## Git workflow

1. Create a feature branch from `main`/`work`.
2. Write commits clearly (`component: short description`).
3. Each change must contain:
   * implementation + tests,
   * updated documentation (`/spec`, README, ADR),
   * entry in `CHANGELOG.md` (if it changes behavior).
4. Open a PR with the filled template and attached test outputs.

## Testing and security

* `cargo test --workspace --all-targets --locked`
* `cargo clippy --workspace --all-targets --all-features -- -D warnings`
* `cargo deny check` + `cargo audit --deny warnings`
* In case of security incident, follow [SECURITY.md](./SECURITY.md).

## Documentation

* Keep specifications in the [`spec/`](./spec/README.md) directory. Accompany each major protocol update with an ADR (`docs/ADR-XXXX.md`).
* Release process is described in [`spec/build.md`](./spec/build.md).

## Communication

* Technical discussions: GitHub Issues + weekly sync.
* Security reports: see [Security disclosures](https://pq-priv.example.com/security).

Thank you for following the standards – security and auditability have the highest priority.
