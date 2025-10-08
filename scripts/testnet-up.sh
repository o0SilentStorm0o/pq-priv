#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEFAULT_BLOCKS=128
BLOCKS=${BLOCKS:-$DEFAULT_BLOCKS}

export RUST_LOG="info"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --release --bin node
"$ROOT_DIR/target/release/node" run --blocks "$BLOCKS"
