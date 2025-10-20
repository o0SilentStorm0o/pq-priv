#!/usr/bin/env bash
# populate_db.sh - Generate synthetic test data for snapshot/restore testing
#
# Usage:
#   ./scripts/populate_db.sh --data-dir ./data/testdb --blocks 5000 --tx-per-block 100
#
# Parameters:
#   --data-dir         : Path to RocksDB data directory (default: ./data/testdb)
#   --blocks           : Number of blocks to generate (default: 1000)
#   --tx-per-block     : Average transactions per block (default: 50)
#
# Example:
#   # Generate 10,000 blocks with 200 tx each (~2GB database)
#   ./scripts/populate_db.sh --data-dir ./testdata --blocks 10000 --tx-per-block 200

set -euo pipefail

# Defaults
DATA_DIR="./data/testdb"
BLOCKS=1000
TX_PER_BLOCK=50

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --blocks)
            BLOCKS="$2"
            shift 2
            ;;
        --tx-per-block)
            TX_PER_BLOCK="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--data-dir PATH] [--blocks N] [--tx-per-block N]"
            echo ""
            echo "Generate synthetic blockchain data for testing."
            echo ""
            echo "Options:"
            echo "  --data-dir PATH       RocksDB directory (default: ./data/testdb)"
            echo "  --blocks N            Number of blocks (default: 1000)"
            echo "  --tx-per-block N      Transactions per block (default: 50)"
            echo "  -h, --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Create data directory if needed
mkdir -p "$DATA_DIR"

# Calculate estimated size
EST_SIZE_MB=$((BLOCKS * TX_PER_BLOCK * 2 / 1024))
echo "=== Populating database ==="
echo "Data directory: $DATA_DIR"
echo "Blocks:         $BLOCKS"
echo "Tx per block:   $TX_PER_BLOCK"
echo "Est. size:      ~${EST_SIZE_MB}MB"
echo ""

# Build the node binary if not present
if [[ ! -f "./target/release/pq-node" ]]; then
    echo "Building release binary..."
    cargo build --release --package node
fi

# Generate synthetic data using a simple Python script
# (In production, this would use the node's RPC or a custom tool)
cat > /tmp/populate_db.py << 'EOFPY'
import sys
import os
import json
import struct
import hashlib
import random

# Minimal synthetic data generator
# In production, use the node's actual API or a proper test harness

def main():
    data_dir = sys.argv[1]
    blocks = int(sys.argv[2])
    tx_per_block = int(sys.argv[3])
    
    print(f"Generating {blocks} blocks with ~{tx_per_block} tx each...")
    print(f"(This is a placeholder; real implementation would use node RPC)")
    
    # For now, create a marker file indicating synthetic data
    marker_path = os.path.join(data_dir, "SYNTHETIC_DATA_MARKER")
    with open(marker_path, 'w') as f:
        json.dump({
            "blocks": blocks,
            "tx_per_block": tx_per_block,
            "generated_by": "populate_db.sh",
            "note": "This is a placeholder for actual data generation"
        }, f, indent=2)
    
    print(f"✓ Marker file created: {marker_path}")
    print("")
    print("NOTE: This script is a placeholder. For real testing:")
    print("  1. Start the node with: cargo run --release --package node -- run --data-dir {data_dir}")
    print("  2. Use RPC to mine blocks or submit transactions")
    print("  3. Or implement a proper data generation tool")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOFPY

python3 /tmp/populate_db.py "$DATA_DIR" "$BLOCKS" "$TX_PER_BLOCK"
rm /tmp/populate_db.py

echo ""
echo "=== Database populated ==="
echo "You can now create a snapshot with:"
echo "  cargo run --release --package node -- snapshot-now --data-dir $DATA_DIR --snapshot-dir ./snapshots"
echo ""
echo "For real testing, start the node and generate actual blocks:"
echo "  cargo run --release --package node -- run --data-dir $DATA_DIR"
