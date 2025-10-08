#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TESTNET_DIR="$ROOT_DIR/.testnet"
PID_FILE="$TESTNET_DIR/node.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No running pq-priv testnet node found (missing PID file)." >&2
  exit 0
fi

NODE_PID=$(cat "$PID_FILE")
if ! kill -0 "$NODE_PID" 2>/dev/null; then
  echo "Stale PID file detected for process $NODE_PID; cleaning up." >&2
  rm -f "$PID_FILE"
  exit 0
fi

kill "$NODE_PID"
wait "$NODE_PID" 2>/dev/null || true
rm -f "$PID_FILE"

echo "Terminated pq-priv testnet node (PID $NODE_PID)."
