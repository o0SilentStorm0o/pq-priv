# Snapshot and Restore Guide

## Overview

The snapshot/restore functionality allows you to create consistent backups of the blockchain database and restore them on the same or different machines. Snapshots are stored as compressed tar.gz archives with metadata validation.

## Snapshot Format

### Archive Structure

```
snap-0000001000-1698765432.tar.gz
├── metadata.json
└── checkpoint/
    ├── CURRENT
    ├── MANIFEST-*
    ├── *.sst
    └── ... (RocksDB checkpoint files)
```

### Metadata Schema

`metadata.json` contains:

```json
{
  "height": 1000,
  "tip_hash": "a1b2c3d4...",
  "cumulative_work": "3039",
  "utxo_count": 5000,
  "timestamp": 1698765432,
  "column_families": ["default", "headers", "blocks", "utxos"],
  "format_version": 1
}
```

**Fields:**
- `height`: Block height at snapshot time
- `tip_hash`: Hex-encoded tip block hash (32 bytes)
- `cumulative_work`: Hex-encoded cumulative chain work
- `utxo_count`: Total UTXOs in the set
- `timestamp`: Unix timestamp when snapshot was created
- `column_families`: List of RocksDB column families included
- `format_version`: Snapshot format version (currently 1)

## Security Features

### Path Traversal Protection

- All paths are canonicalized before operations
- Rejects absolute paths in archives
- Rejects `..` components (path traversal attempts)
- Validates extracted files stay within target directory

### Symlink Protection

- Hard links and symbolic links are **explicitly rejected**
- Archive extraction fails immediately if symlink detected
- Prevents attacks via symlink to sensitive files (e.g., `/etc/passwd`)

### Atomic Operations

- Snapshots written to `.tmp` file, then atomically renamed
- Restore extracts to temporary directory first
- Only moves to target directory after full validation
- No partial snapshots or corrupt restores

## CLI Commands

### Create Snapshot

**One-time snapshot:**

```bash
node snapshot-now \
  --db-path ./data/db \
  --snapshot-dir ./snapshots
```

**Automatic snapshots during node operation:**

```bash
node run \
  --config node.toml \
  --snapshot-interval 1000 \
  --snapshot-dir ./snapshots \
  --snapshot-keep 5
```

- `--snapshot-interval <blocks>`: Create snapshot every N blocks (0 = disabled)
- `--snapshot-keep <count>`: Keep only N most recent snapshots (older are deleted)

### Restore Snapshot

```bash
node restore-snapshot \
  --snapshot-path ./snapshots/snap-0000001000-1698765432.tar.gz \
  --target-dir ./restored-db
```

**Validation after restore:**
- Verifies `tip_hash` matches metadata
- Verifies `height` matches metadata
- Exits with code 0 on success, non-zero on failure

### Verify Snapshot

```bash
node verify-snapshot \
  --snapshot-path ./snapshots/snap-0000001000-1698765432.tar.gz
```

**What it checks:**
- Archive can be decompressed
- `metadata.json` is valid JSON
- `format_version` is supported (currently 1)
- `tip_hash` and `cumulative_work` are valid hex
- Checkpoint directory exists and contains files

**Exit codes:**
- `0`: Snapshot is valid
- `1`: Snapshot is corrupt or invalid

## Helper Scripts

### `scripts/populate_db.sh`

Populates database with test blocks and transactions for large dataset testing.

**Usage:**

```bash
bash scripts/populate_db.sh <data-dir> <blocks> <tx-per-block>
```

**Example (create ~5GB dataset):**

```bash
bash scripts/populate_db.sh ./.pqpriv_large 120000 10
```

**Parameters:**
- `data-dir`: Directory for blockchain data
- `blocks`: Number of blocks to generate
- `tx-per-block`: Transactions per block (affects UTXO set size)

### `scripts/snapshot-restore-verify.sh`

End-to-end test: creates snapshot → deletes DB → restores → verifies integrity.

**Usage:**

```bash
bash scripts/snapshot-restore-verify.sh <snapshot-path>
```

**Example:**

```bash
bash scripts/snapshot-restore-verify.sh ./snapshots/snap-0000001000-1698765432.tar.gz
```

**Exit codes:**
- `0`: Snapshot/restore cycle successful
- `1`: Verification failed (tip hash or height mismatch)
- `2`: Metadata parsing failed

## Configuration

### TOML Configuration

```toml
# node.toml
snapshots_path = "./snapshots"
snapshot_interval = 1000  # Create snapshot every 1000 blocks
snapshot_keep = 5         # Keep 5 most recent snapshots
```

### Environment Variables

```bash
# Override snapshot directory
export SNAPSHOT_DIR=/var/lib/pqpriv/snapshots

# Override snapshot interval
export SNAPSHOT_INTERVAL=5000
```

### CLI Override Precedence

```
CLI flags > Environment variables > TOML config > Defaults
```

## Limitations and Known Issues

### Current Limitations

1. **UTXO Count Approximation**: Currently uses block height as proxy for UTXO count (TODO: implement actual UTXO scanning)
2. **No Incremental Snapshots**: Each snapshot is full database copy
3. **No Compression Level Control**: Uses default gzip compression
4. **No Snapshot Encryption**: Snapshots are unencrypted tar.gz archives

### Performance Considerations

- **Snapshot creation time**: ~1-2s per GB (depends on disk speed)
- **Archive size**: ~30-50% of database size (with compression)
- **Restore time**: ~2-3s per GB (extraction + validation)

### Storage Requirements

For a 10GB database:
- Snapshot file: ~3-5GB
- Temporary space during creation: ~10GB (checkpoint copy)
- Temporary space during restore: ~10GB (extraction)

## Troubleshooting

### "Directory exists" error during snapshot

**Cause:** RocksDB checkpoint creation failed because target directory already exists.

**Solution:** Temporary directory is automatically cleaned up. If error persists, manually remove `<snapshot-dir>/temp-*` directories.

### "Unexpected end of file" during restore

**Cause:** Incomplete or corrupt snapshot archive.

**Solution:** Re-create snapshot from source database. Verify network transfer integrity if copying between machines.

### "Invalid tip hash" after restore

**Cause:** Database state doesn't match snapshot metadata.

**Solution:** This indicates data corruption. Do not use this snapshot. Create a new snapshot from a known-good database.

## Best Practices

### Production Deployments

1. **Schedule snapshots during low-traffic periods**: Snapshot creation briefly pauses block acceptance
2. **Use separate disk for snapshots**: Avoid I/O contention with main database
3. **Verify snapshots immediately after creation**: Run `verify-snapshot` to catch issues early
4. **Test restore procedure regularly**: Monthly test restores to separate instance
5. **Monitor snapshot metrics**: Track `node_snapshot_last_duration_ms` and `node_snapshot_failures_total`

### Disaster Recovery

1. Keep snapshots on separate physical storage (NAS, S3, etc.)
2. Maintain at least 3 snapshots (daily, weekly, monthly)
3. Document restore procedure for on-call team
4. Test restore time meets RTO requirements

### Security Recommendations

1. **Validate snapshot source**: Only restore from trusted snapshots
2. **Check file permissions**: Snapshots should be readable only by node process user
3. **Scan for tampering**: Verify checksums/signatures if transferring over network
4. **Audit logs**: Log all snapshot/restore operations with timestamps and actors

## Metrics

The following Prometheus metrics are exposed:

- `node_snapshot_count_total`: Total snapshots created
- `node_snapshot_last_duration_ms`: Duration of last snapshot creation
- `node_snapshot_last_height`: Block height of last snapshot
- `node_snapshot_failures_total`: Total failed snapshot attempts
- `node_restore_count_total`: Total restore operations performed
- `node_restore_failures_total`: Total failed restore attempts

## Testing

### Unit Tests

Run snapshot/restore unit tests:

```bash
cargo test --package storage --test snapshot_tests
```

**Test coverage:**
- ✅ Metadata serialization roundtrip
- ✅ Full snapshot/restore cycle
- ✅ Symlink rejection (Unix only)
- ✅ Path traversal rejection
- ✅ Malformed metadata validation
- ✅ Unsupported format version rejection
- ✅ Snapshot listing and cleanup

### Integration Tests

Run full node integration tests:

```bash
cargo test --workspace
```

### Large Dataset Smoke Test

```bash
# 1. Populate large database (~5GB)
bash scripts/populate_db.sh ./.pqpriv_large 120000 10

# 2. Create snapshot
target/release/node snapshot-now \
  --db-path ./.pqpriv_large \
  --snapshot-dir ./snapshots

# 3. Verify and restore
bash scripts/snapshot-restore-verify.sh ./snapshots/snap-*.tar.gz
```

## Future Enhancements

- [ ] Incremental snapshots (delta-based)
- [ ] Streaming compression (reduce temp disk usage)
- [ ] Snapshot encryption (at-rest security)
- [ ] Automatic snapshot upload to S3/Azure Blob
- [ ] Multi-threaded compression (faster snapshots)
- [ ] Actual UTXO count scanning (remove approximation)
- [ ] Snapshot integrity signatures (prevent tampering)
- [ ] Retention policies (time-based, not just count-based)

## References

- [RocksDB Checkpoint Documentation](https://github.com/facebook/rocksdb/wiki/Checkpoints)
- [Sprint 4 Blueprint](../spec/sprint3_plan.md)
- [Storage Architecture](./perf/storage.md)
- [Security Audit Report](../SECURITY_AUDIT.md)
