#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEFAULT_BLOCKS=128
DEFAULT_LOG_TAIL=50
BLOCKS=${BLOCKS:-$DEFAULT_BLOCKS}
LOG_TAIL=${LOG_TAIL:-$DEFAULT_LOG_TAIL}
TESTNET_DIR="$ROOT_DIR/.testnet"
PID_FILE="$TESTNET_DIR/node.pid"
LOG_FILE="$TESTNET_DIR/node.log"

mkdir -p "$TESTNET_DIR"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Testnet node already running with PID $(cat "$PID_FILE")" >&2
  exit 0
fi

export RUST_LOG="${RUST_LOG:-info}"

if [[ -n "${CARGO:-}" ]]; then
  # shellcheck disable=SC2206
  CARGO_CMD=(${CARGO})
elif command -v cargo >/dev/null 2>&1; then
  CARGO_CMD=(cargo)
elif command -v powershell.exe >/dev/null 2>&1; then
  CARGO_PATH_WIN=$(powershell.exe -NoProfile -Command "Get-Command cargo | Select-Object -ExpandProperty Source" | tr -d '\r')
  if [[ -z "$CARGO_PATH_WIN" ]]; then
    echo "Error: unable to locate cargo binary via powershell." >&2
    exit 127
  fi
  if command -v wslpath >/dev/null 2>&1; then
    CARGO_PATH=$(wslpath -u "$CARGO_PATH_WIN")
  else
    CARGO_PATH="$CARGO_PATH_WIN"
  fi
  CARGO_CMD=("$CARGO_PATH")
  USE_WINDOWS_PATHS=1
else
  echo "Error: cargo command not found. Install Rust or set the CARGO environment variable." >&2
  exit 127
fi

MANIFEST_PATH="$ROOT_DIR/Cargo.toml"
if [[ ${USE_WINDOWS_PATHS:-0} -eq 1 ]]; then
  MANIFEST_PATH=$(wslpath -w "$MANIFEST_PATH")
fi

"${CARGO_CMD[@]}" build --manifest-path "$MANIFEST_PATH" --release --bin node

NODE_BIN="$ROOT_DIR/target/release/node"
if [[ ! -x "$NODE_BIN" && -x "${NODE_BIN}.exe" ]]; then
  NODE_BIN="${NODE_BIN}.exe"
fi

"$NODE_BIN" run --blocks "$BLOCKS" \
  >"$LOG_FILE" 2>&1 &
NODE_PID=$!

echo "$NODE_PID" > "$PID_FILE"

echo "Started pq-priv testnet node (PID $NODE_PID). Logs: $LOG_FILE"

HEALTH_TIMEOUT=10
CHECK_INTERVAL=0.5
ITERATIONS=20
SUCCESS=0

for ((i=0; i<ITERATIONS; i++)); do
  if grep -q "Mined block" "$LOG_FILE" 2>/dev/null; then
    SUCCESS=1
    break
  fi
  sleep "$CHECK_INTERVAL"
done

if [[ $SUCCESS -eq 1 ]]; then
  echo "Testnet node reported mining activity within ${HEALTH_TIMEOUT}s."
else
  echo "Warning: no 'Mined block' entry detected within ${HEALTH_TIMEOUT}s." >&2
fi

echo "--- Last ${LOG_TAIL} log lines ---"
tail -n "$LOG_TAIL" "$LOG_FILE" || true
