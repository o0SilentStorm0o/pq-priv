# Contributing to PQ-PRIV

## Quick Start
```bash
# toolchain (Rust 1.90+ with edition 2024 support)
rustup default stable
rustup component add clippy rustfmt

# workspace build & tests
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace -- -D warnings
cargo fmt   --all -- --check


