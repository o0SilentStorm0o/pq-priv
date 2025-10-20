#!/usr/bin/env bash
# e2e-reporter.sh - Collect metrics and generate summary report from E2E tests
#
# Usage:
#   ./scripts/e2e-reporter.sh <topology> <port1> <port2> [port3] [port4]
#
# Examples:
#   ./scripts/e2e-reporter.sh line 8545 8546 8547
#   ./scripts/e2e-reporter.sh star 8550 8551 8552 8553
#   ./scripts/e2e-reporter.sh partition 8560 8561 8562

set -euo pipefail

TOPOLOGY="${1:-unknown}"
shift

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <topology> <port1> <port2> [port3] [port4]" >&2
    echo "" >&2
    echo "Examples:" >&2
    echo "  $0 line 8545 8546 8547" >&2
    echo "  $0 star 8550 8551 8552 8553" >&2
    echo "  $0 partition 8560 8561 8562" >&2
    exit 1
fi

PORTS=("$@")
REPORT_DIR="docker/e2e/report"
mkdir -p "$REPORT_DIR"

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
REPORT_FILE="${REPORT_DIR}/summary_${TOPOLOGY}_${TIMESTAMP}.json"

echo "=== E2E Reporter: $TOPOLOGY ===" >&2
echo "Collecting metrics from ${#PORTS[@]} nodes..." >&2
echo "" >&2

# Initialize JSON structure
cat > "$REPORT_FILE" << EOF
{
  "topology": "$TOPOLOGY",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "nodes": []
}
EOF

# Collect from each node
for i in "${!PORTS[@]}"; do
    PORT="${PORTS[$i]}"
    NODE_NAME="node_$((i+1))"
    
    echo "[$NODE_NAME] Fetching from localhost:$PORT..." >&2
    
    # Fetch chain tip (assuming JSON RPC endpoint)
    TIP_JSON=$(curl -sf "http://localhost:$PORT/chain/tip" || echo '{"error": "unreachable"}')
    TIP_HEIGHT=$(echo "$TIP_JSON" | jq -r '.height // "N/A"' 2>/dev/null || echo "N/A")
    TIP_HASH=$(echo "$TIP_JSON" | jq -r '.hash // "N/A"' 2>/dev/null || echo "N/A")
    
    # Fetch Prometheus metrics
    METRICS=$(curl -sf "http://localhost:$PORT/metrics" || echo "")
    
    # Parse relevant metrics
    REORG_COUNT=$(echo "$METRICS" | grep '^node_reorg_count_total ' | awk '{print $2}' || echo "0")
    ORPHAN_POOL=$(echo "$METRICS" | grep '^node_orphan_pool_size ' | awk '{print $2}' || echo "0")
    DB_SIZE=$(echo "$METRICS" | grep '^node_db_size_bytes ' | awk '{print $2}' || echo "0")
    PEER_COUNT=$(echo "$METRICS" | grep '^pqpriv_peers ' | awk '{print $2}' || echo "0")
    
    # Append to JSON (using jq for proper formatting)
    TMP_NODE=$(mktemp)
    cat > "$TMP_NODE" << EOF
{
  "name": "$NODE_NAME",
  "port": $PORT,
  "tip_height": "$TIP_HEIGHT",
  "tip_hash": "$TIP_HASH",
  "reorg_count": ${REORG_COUNT:-0},
  "orphan_pool_size": ${ORPHAN_POOL:-0},
  "db_size_bytes": ${DB_SIZE:-0},
  "peer_count": ${PEER_COUNT:-0}
}
EOF
    
    # Merge into report
    jq ".nodes += [$(cat "$TMP_NODE")]" "$REPORT_FILE" > "${REPORT_FILE}.tmp"
    mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
    rm "$TMP_NODE"
    
    echo "  ✓ tip_height=$TIP_HEIGHT, tip_hash=${TIP_HASH:0:16}..., peers=$PEER_COUNT" >&2
done

echo "" >&2
echo "=== Summary ===" >&2
jq -r '.nodes[] | "[\(.name)] height=\(.tip_height), reorgs=\(.reorg_count), orphans=\(.orphan_pool_size), db_size=\(.db_size_bytes)"' "$REPORT_FILE" >&2

echo "" >&2
echo "Report saved to: $REPORT_FILE" >&2

# Check consensus (all nodes have same tip_hash)
UNIQUE_HASHES=$(jq -r '.nodes[].tip_hash' "$REPORT_FILE" | sort -u | wc -l)
if [[ "$UNIQUE_HASHES" -eq 1 ]]; then
    echo "✓ Consensus reached: All nodes have identical tip_hash" >&2
    exit 0
else
    echo "❌ Consensus failed: Nodes have different tip_hash values" >&2
    jq -r '.nodes[] | "  \(.name): \(.tip_hash)"' "$REPORT_FILE" >&2
    exit 1
fi
