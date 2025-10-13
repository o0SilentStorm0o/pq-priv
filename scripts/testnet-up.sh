#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEFAULT_LOG_TAIL=50
LOG_TAIL=${LOG_TAIL:-$DEFAULT_LOG_TAIL}
TESTNET_DIR="$ROOT_DIR/.testnet"
PID_FILE="$TESTNET_DIR/node.pid"
LOG_FILE="$TESTNET_DIR/node.log"
CONFIG_FILE_POSIX="$TESTNET_DIR/node.toml"

CONFIG_PATH_POSIX=""
CONFIG_PATH_NODE=""
NODE_PID=""

cleanup() {
  stop_node
}
trap cleanup EXIT

fail_with_logs() {
  echo "Error: $1" >&2
  if [[ -f "$LOG_FILE" ]]; then
    echo "--- Last ${LOG_TAIL} log lines ---" >&2
    tail -n "$LOG_TAIL" "$LOG_FILE" >&2 || true
  fi
  exit 1
}

stop_node() {
  if [[ -n "${NODE_PID:-}" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill "$NODE_PID" 2>/dev/null || true
    for _ in {1..20}; do
      if ! kill -0 "$NODE_PID" 2>/dev/null; then
        break
      fi
      sleep 0.5
    done
    if kill -0 "$NODE_PID" 2>/dev/null; then
      if command -v taskkill.exe >/dev/null 2>&1; then
        taskkill.exe /PID "$NODE_PID" /T /F >/dev/null 2>&1 || true
      fi
    fi
    wait "$NODE_PID" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  NODE_PID=""
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: required tool '$tool' is not installed. Please install it and retry." >&2
    exit 127
  fi
}

extract_config_value() {
  local key="$1"
  sed -n -E "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*\"([^\"]+)\"[[:space:]]*$/\1/p" "$CONFIG_PATH_POSIX" | head -n1
}

wait_for_health() {
  local url="$1"
  local attempts=20
  for ((i=0; i<attempts; i++)); do
    if response=$(curl --silent --show-error --fail "$url" 2>/dev/null); then
      local status
      status=$(echo "$response" | jq -r '.status // empty' 2>/dev/null || true)
      if [[ "$status" == "ok" ]]; then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
}

fetch_chain_tip() {
  curl --silent --show-error --fail "$RPC_URL/chain/tip"
}

start_node() {
  "$NODE_BIN" run --config "$CONFIG_PATH_NODE" >>"$LOG_FILE" 2>&1 &
  NODE_PID=$!
  echo "$NODE_PID" > "$PID_FILE"
}

REQUIRED_CMDS=(curl jq)
for tool in "${REQUIRED_CMDS[@]}"; do
  require_tool "$tool"
done

mkdir -p "$TESTNET_DIR"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Testnet node already running with PID $(cat "$PID_FILE")" >&2
  exit 1
fi

> "$LOG_FILE"

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

if [[ -n "${BLOCKS:-}" ]]; then
  echo "Warning: BLOCKS environment variable is deprecated and ignored." >&2
fi

if [[ -n "${NODE_FEATURES:-}" ]]; then
  # shellcheck disable=SC2206
  FEATURE_ARGS=(${NODE_FEATURES})
else
  FEATURE_ARGS=(--features devnet)
fi

MANIFEST_PATH="$ROOT_DIR/Cargo.toml"
if [[ ${USE_WINDOWS_PATHS:-0} -eq 1 ]]; then
  MANIFEST_PATH=$(wslpath -w "$MANIFEST_PATH")
fi

"${CARGO_CMD[@]}" build --manifest-path "$MANIFEST_PATH" --release "${FEATURE_ARGS[@]}" --bin node

NODE_BIN="$ROOT_DIR/target/release/node"
if [[ ! -x "$NODE_BIN" && -x "${NODE_BIN}.exe" ]]; then
  NODE_BIN="${NODE_BIN}.exe"
fi

if [[ -n "${NODE_CONFIG:-}" ]]; then
  CONFIG_PATH_INPUT="${NODE_CONFIG}"
  if [[ "$CONFIG_PATH_INPUT" =~ ^[A-Za-z]:\\ ]]; then
    if command -v wslpath >/dev/null 2>&1; then
      CONFIG_PATH_POSIX=$(wslpath -u "$CONFIG_PATH_INPUT")
    else
      echo "Error: cannot convert Windows path '$CONFIG_PATH_INPUT' (wslpath missing)." >&2
      exit 1
    fi
  elif [[ "$CONFIG_PATH_INPUT" == /* ]]; then
    CONFIG_PATH_POSIX="$CONFIG_PATH_INPUT"
  else
    CONFIG_PATH_POSIX="$ROOT_DIR/$CONFIG_PATH_INPUT"
  fi
else
  CONFIG_PATH_POSIX="$CONFIG_FILE_POSIX"
  cat > "$CONFIG_PATH_POSIX" <<EOF
p2p_listen = "127.0.0.1:18444"
rpc_listen = "127.0.0.1:18445"
db_path = ".testnet/node"
snapshots_path = ".testnet/snapshots"
EOF
fi

if [[ ! -f "$CONFIG_PATH_POSIX" ]]; then
  echo "Error: configuration file '$CONFIG_PATH_POSIX' not found." >&2
  exit 1
fi

if [[ ${USE_WINDOWS_PATHS:-0} -eq 1 ]] && command -v wslpath >/dev/null 2>&1 && [[ "$CONFIG_PATH_POSIX" == /* ]]; then
  CONFIG_PATH_NODE=$(wslpath -w "$CONFIG_PATH_POSIX")
else
  CONFIG_PATH_NODE="$CONFIG_PATH_POSIX"
fi

RPC_LISTEN=$(extract_config_value "rpc_listen")
P2P_LISTEN=$(extract_config_value "p2p_listen")

if [[ -z "$RPC_LISTEN" || -z "$P2P_LISTEN" ]]; then
  echo "Error: unable to read rpc_listen or p2p_listen from configuration." >&2
  exit 1
fi

if [[ "$RPC_LISTEN" == *":0" || "$P2P_LISTEN" == *":0" ]]; then
  echo "Error: integration test requires fixed ports (rpc_listen/p2p_listen must not use :0)." >&2
  exit 1
fi

RPC_URL="http://$RPC_LISTEN"

mkdir -p "$TESTNET_DIR/node" "$TESTNET_DIR/snapshots"

start_node
echo "Started pq-priv testnet node (PID $NODE_PID). Logs: $LOG_FILE"

if ! wait_for_health "$RPC_URL/health"; then
  fail_with_logs "RPC health endpoint did not report ready state within timeout."
fi
echo "RPC health OK ($RPC_LISTEN)"

tip_json=$(fetch_chain_tip) || fail_with_logs "Failed to fetch chain tip."
tip_height=$(echo "$tip_json" | jq -r '.height // empty')
tip_hash=$(echo "$tip_json" | jq -r '.hash // empty' | tr 'A-F' 'a-f')

if [[ "$tip_height" != "0" ]]; then
  fail_with_logs "Unexpected chain height at startup: expected 0, got ${tip_height:-<missing>}."
fi

if [[ -z "$tip_hash" ]]; then
  fail_with_logs "Chain tip hash missing after health check."
fi

echo "Tip OK @ height=0 (hash=$tip_hash)"

if ! mine_resp=$(curl --silent --show-error --fail -X POST "$RPC_URL/dev/mine" 2>/dev/null); then
  fail_with_logs "Mining endpoint failed; ensure the node was built with the 'devnet' feature."
fi

mine_height=$(echo "$mine_resp" | jq -r '.height // empty')
if [[ -z "$mine_height" || "$mine_height" == "null" ]]; then
  fail_with_logs "Mining response missing height: $mine_resp"
fi

tip_after=$(fetch_chain_tip) || fail_with_logs "Failed to fetch chain tip after mining."
height_after=$(echo "$tip_after" | jq -r '.height // empty')
if [[ -z "$height_after" || "$height_after" == "null" || "$height_after" -lt "$mine_height" ]]; then
  fail_with_logs "Chain height did not advance after mining (expected >= $mine_height, got ${height_after:-<missing>})."
fi

echo "Height advanced to $height_after"

sleep 1
stop_node

start_node

if ! wait_for_health "$RPC_URL/health"; then
  fail_with_logs "RPC health endpoint did not recover after restart."
fi

tip_restart=$(fetch_chain_tip) || fail_with_logs "Failed to fetch chain tip after restart."
height_restart=$(echo "$tip_restart" | jq -r '.height // empty')
if [[ -z "$height_restart" || "$height_restart" -lt "$height_after" ]]; then
  fail_with_logs "Chain height regressed after restart (before=$height_after, after=${height_restart:-<missing>})."
fi

echo "Persistence OK (height=$height_restart)"

stop_node

echo "--- Last ${LOG_TAIL} log lines ---"
tail -n "$LOG_TAIL" "$LOG_FILE" || true

exit 0


