#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEFAULT_BLOCKS=128
BLOCKS=${BLOCKS:-$DEFAULT_BLOCKS}
TESTNET_DIR="$ROOT_DIR/.testnet"
PID_FILE="$TESTNET_DIR/node.pid"
LOG_FILE="$TESTNET_DIR/node.log"

mkdir -p "$TESTNET_DIR"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Testnet node already running with PID $(cat "$PID_FILE")" >&2
  exit 0
fi

export RUST_LOG="info"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --release --bin node
"$ROOT_DIR/target/release/node" run --blocks "$BLOCKS" \
  >"$LOG_FILE" 2>&1 &
NODE_PID=$!

echo "$NODE_PID" > "$PID_FILE"

echo "Started pq-priv testnet node (PID $NODE_PID). Logs: $LOG_FILE"
