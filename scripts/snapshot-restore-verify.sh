#!/usr/bin/env bash
# snapshot-restore-verify.sh - End-to-end snapshot/restore verification script
#
# Usage:
#   ./scripts/snapshot-restore-verify.sh --data-dir ./data/testdb --snapshot-dir ./snapshots
#
# Parameters:
#   --data-dir       : Path to RocksDB data directory (default: ./data/testdb)
#   --snapshot-dir   : Path to snapshot directory (default: ./snapshots)
#   --keep-snapshot  : Don't delete the created snapshot after test (optional)
#
# Exit codes:
#   0  - Success: snapshot created, DB deleted, restored, and verified
#   1  - Failure: one or more steps failed
#
# Example:
#   ./scripts/snapshot-restore-verify.sh --data-dir ./testdata --snapshot-dir ./test-snaps

set -euo pipefail

# Defaults
DATA_DIR="./data/testdb"
SNAPSHOT_DIR="./snapshots"
KEEP_SNAPSHOT=false
CARGO_BIN="cargo run --release --package node --"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --snapshot-dir)
            SNAPSHOT_DIR="$2"
            shift 2
            ;;
        --keep-snapshot)
            KEEP_SNAPSHOT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--data-dir PATH] [--snapshot-dir PATH] [--keep-snapshot]"
            echo ""
            echo "Verify snapshot/restore functionality with the following steps:"
            echo "  1. Create a snapshot of existing database"
            echo "  2. Record original tip height and hash"
            echo "  3. Delete the database directory"
            echo "  4. Restore from snapshot"
            echo "  5. Verify tip height and hash match"
            echo ""
            echo "Options:"
            echo "  --data-dir PATH       RocksDB directory (default: ./data/testdb)"
            echo "  --snapshot-dir PATH   Snapshot directory (default: ./snapshots)"
            echo "  --keep-snapshot       Don't delete snapshot after test"
            echo "  -h, --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Create directories if needed
mkdir -p "$DATA_DIR"
mkdir -p "$SNAPSHOT_DIR"

echo "=== Snapshot/Restore Verification ==="
echo "Data directory:     $DATA_DIR"
echo "Snapshot directory: $SNAPSHOT_DIR"
echo ""

# Check if database exists
if [[ ! -d "$DATA_DIR" ]] || [[ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ]]; then
    echo "❌ Error: Database directory is empty or does not exist: $DATA_DIR" >&2
    echo "   Run populate_db.sh first or start the node to create data." >&2
    exit 1
fi

# Build release binary if needed
if [[ ! -f "./target/release/pq-node" ]]; then
    echo "Building release binary..."
    cargo build --release --package node
fi

# Step 1: Create snapshot
echo "Step 1: Creating snapshot..."
SNAPSHOT_OUTPUT=$(mktemp)
if ! $CARGO_BIN snapshot-now --data-dir "$DATA_DIR" --snapshot-dir "$SNAPSHOT_DIR" > "$SNAPSHOT_OUTPUT" 2>&1; then
    echo "❌ Snapshot creation failed:" >&2
    cat "$SNAPSHOT_OUTPUT" >&2
    rm "$SNAPSHOT_OUTPUT"
    exit 1
fi

# Parse snapshot filename and metadata from output
SNAPSHOT_FILE=$(grep -oP 'Created snapshot: \K[^ ]+' "$SNAPSHOT_OUTPUT" || echo "")
TIP_HEIGHT_ORIG=$(grep -oP 'Tip height: \K[0-9]+' "$SNAPSHOT_OUTPUT" || echo "")
TIP_HASH_ORIG=$(grep -oP 'Tip hash: \K[a-f0-9]+' "$SNAPSHOT_OUTPUT" || echo "")

if [[ -z "$SNAPSHOT_FILE" ]]; then
    echo "❌ Could not parse snapshot filename from output:" >&2
    cat "$SNAPSHOT_OUTPUT" >&2
    rm "$SNAPSHOT_OUTPUT"
    exit 1
fi

echo "✓ Snapshot created: $SNAPSHOT_FILE"
echo "  Original tip height: $TIP_HEIGHT_ORIG"
echo "  Original tip hash:   $TIP_HASH_ORIG"
rm "$SNAPSHOT_OUTPUT"
echo ""

# Step 2: Delete database directory
echo "Step 2: Deleting database directory..."
if ! rm -rf "$DATA_DIR"; then
    echo "❌ Failed to delete database directory: $DATA_DIR" >&2
    exit 1
fi
echo "✓ Database deleted"
echo ""

# Step 3: Restore from snapshot
echo "Step 3: Restoring from snapshot..."
RESTORE_OUTPUT=$(mktemp)
if ! $CARGO_BIN restore-snapshot --snapshot-file "$SNAPSHOT_FILE" --data-dir "$DATA_DIR" > "$RESTORE_OUTPUT" 2>&1; then
    echo "❌ Restore failed:" >&2
    cat "$RESTORE_OUTPUT" >&2
    rm "$RESTORE_OUTPUT"
    exit 1
fi

# Parse restored metadata
TIP_HEIGHT_REST=$(grep -oP 'Tip height: \K[0-9]+' "$RESTORE_OUTPUT" || echo "")
TIP_HASH_REST=$(grep -oP 'Tip hash: \K[a-f0-9]+' "$RESTORE_OUTPUT" || echo "")

echo "✓ Snapshot restored"
echo "  Restored tip height: $TIP_HEIGHT_REST"
echo "  Restored tip hash:   $TIP_HASH_REST"
rm "$RESTORE_OUTPUT"
echo ""

# Step 4: Verify tip height and hash match
echo "Step 4: Verifying data integrity..."
VERIFICATION_FAILED=false

if [[ "$TIP_HEIGHT_ORIG" != "$TIP_HEIGHT_REST" ]]; then
    echo "❌ Tip height mismatch!" >&2
    echo "   Original: $TIP_HEIGHT_ORIG" >&2
    echo "   Restored: $TIP_HEIGHT_REST" >&2
    VERIFICATION_FAILED=true
fi

if [[ "$TIP_HASH_ORIG" != "$TIP_HASH_REST" ]]; then
    echo "❌ Tip hash mismatch!" >&2
    echo "   Original: $TIP_HASH_ORIG" >&2
    echo "   Restored: $TIP_HASH_REST" >&2
    VERIFICATION_FAILED=true
fi

if [[ "$VERIFICATION_FAILED" = true ]]; then
    exit 1
fi

echo "✓ Verification passed: tip height and hash match"
echo ""

# Step 5: Cleanup (optional)
if [[ "$KEEP_SNAPSHOT" = false ]]; then
    echo "Step 5: Cleaning up snapshot..."
    if ! rm "$SNAPSHOT_FILE"; then
        echo "⚠️  Warning: Failed to delete snapshot: $SNAPSHOT_FILE" >&2
    else
        echo "✓ Snapshot deleted"
    fi
else
    echo "Step 5: Keeping snapshot (--keep-snapshot flag)"
    echo "  Snapshot: $SNAPSHOT_FILE"
fi

echo ""
echo "=== ✓ All checks passed ==="
exit 0
