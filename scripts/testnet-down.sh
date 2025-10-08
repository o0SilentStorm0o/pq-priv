#!/usr/bin/env bash
set -euo pipefail

PIDS=$(pgrep -f "target/release/node" || true)
if [[ -z "$PIDS" ]]; then
  echo "No running pq-priv nodes discovered." >&2
  exit 0
fi

for pid in $PIDS; do
  kill "$pid"
  wait "$pid" 2>/dev/null || true
done

echo "Terminated $PIDS"
