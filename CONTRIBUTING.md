# Contributing to PQ-PRIV

## Quick Start
```bash
# toolchain
rustup default stable
rustup component add clippy rustfmt

# workspace build & tests
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace -- -D warnings
cargo fmt   --all -- --check


