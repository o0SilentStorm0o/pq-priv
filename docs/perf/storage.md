# Storage Performance Tuning

This document describes RocksDB configuration for PQ-PRIV and provides guidance for optimizing storage performance.

## Quick Start

### Development (Fast Iteration)

For local development and testing:

```rust
use storage::DbTuning;

let tuning = DbTuning::development();
let store = Store::open_with_tuning("./data", tuning)?;
```

**Characteristics:**
- Fast compilation and startup
- Lower memory usage (128 MB cache)
- LZ4 compression (faster than Zstd)
- WAL disabled (faster writes, less durability)
- 2 background jobs (lower CPU usage)

### Production (Durability & Performance)

For production deployments:

```rust
let tuning = DbTuning::production();
let store = Store::open_with_tuning("./data", tuning)?;
```

**Characteristics:**
- Higher memory usage (512 MB cache)
- Zstd compression (better ratio)
- WAL enabled (full durability)
- 8 background jobs (faster compaction)
- Larger write buffers (256 MB)

## Configuration Options

### Via Environment Variables

All tuning parameters can be overridden via environment variables with the `PQPRIV_DB_` prefix:

```bash
export PQPRIV_DB_WRITE_BUFFER_MB=256
export PQPRIV_DB_BLOCK_CACHE_MB=512
export PQPRIV_DB_COMPRESSION=zstd
export PQPRIV_DB_WAL_ENABLED=true
export PQPRIV_DB_MAX_BACKGROUND_JOBS=8
```

### Via CLI (when integrated with node)

```bash
./target/release/node \
  --db.write-buffer-mb 256 \
  --db.block-cache-mb 512 \
  --db.compression zstd \
  --db.wal on
```

### Via Config File (TOML)

```toml
[storage.db_tuning]
max_background_jobs = 8
write_buffer_mb = 256
target_file_size_mb = 128
compaction_dynamic = true
compression = "zstd"
bytes_per_sync_mb = 8
wal_bytes_per_sync_mb = 8
block_cache_mb = 512
readahead_mb = 4
enable_pipelined_write = true
wal_enabled = true
```

## Tuning Parameters Explained

### Memory-Related

| Parameter | Default | Production | Description |
|-----------|---------|------------|-------------|
| `write_buffer_mb` | 128 | 256 | Per-CF write buffer size. Higher = fewer flushes but more memory |
| `block_cache_mb` | 256 | 512 | Shared block cache. Higher = better read performance |
| `readahead_mb` | 2 | 4 | Sequential read buffer. Increase for bulk scans |

**Tuning Tips:**
- Total memory ≈ `write_buffer_mb × 5 (CFs) + block_cache_mb`
- For 8 GB RAM: use defaults
- For 16+ GB RAM: double the production values

### I/O & Compaction

| Parameter | Default | Production | Description |
|-----------|---------|------------|-------------|
| `max_background_jobs` | 4 | 8 | Parallel compaction/flush threads |
| `target_file_size_mb` | 64 | 128 | SST file size target |
| `compaction_dynamic` | true | true | Dynamic level sizing (recommended) |
| `bytes_per_sync_mb` | 4 | 8 | Sync interval for SST writes |
| `wal_bytes_per_sync_mb` | 4 | 8 | Sync interval for WAL writes |

**Tuning Tips:**
- More jobs = faster compaction but higher CPU usage
- Larger SST files = fewer files but slower compaction
- Lower sync intervals = more durable but slower writes

### Compression

| Algorithm | Speed | Ratio | Use Case |
|-----------|-------|-------|----------|
| `none` | Fastest | 1:1 | Testing only |
| `lz4` | Fast | 2-3:1 | Development, low-latency |
| `zstd` | Medium | 3-5:1 | Production (default) |

**Tuning Tips:**
- Use `lz4` for development (faster iteration)
- Use `zstd` for production (saves disk space)
- Compression is per-level; level 0-1 may use different algorithm

### Write-Ahead Log (WAL)

| Parameter | Default | Production | Description |
|-----------|---------|------------|-------------|
| `wal_enabled` | true | true | Enable WAL for durability |

**Tuning Tips:**
- **Always enable WAL in production** for crash recovery
- Disable only for testing/benchmarking
- WAL files are automatically cleaned after checkpoint

## Filesystem & OS Recommendations

### Linux

```bash
# Mount with noatime to reduce metadata writes
sudo mount -o remount,noatime /mnt/data

# Increase file descriptor limit
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Use deadline or noop I/O scheduler for SSDs
echo noop > /sys/block/nvme0n1/queue/scheduler
```

### macOS

```bash
# Increase file descriptor limit
ulimit -n 65536

# For APFS, ensure SSD trim is enabled
sudo trimforce enable
```

### Windows

```powershell
# Ensure NTFS compression is disabled for data directory
fsutil behavior set disablecompression 1

# For best performance, use dedicated SSD/NVMe drive
```

## Storage Requirements

| Workload | Disk Space | IOPS | Throughput |
|----------|-----------|------|------------|
| Full node (1 year) | ~50 GB | 5000+ | 100 MB/s |
| Archive node (full history) | ~500 GB | 10000+ | 200 MB/s |
| Testnet / Dev | ~1 GB | 1000+ | 50 MB/s |

**Recommendations:**
- Use SSD or NVMe (not HDD)
- Ensure at least 2x estimated space for compaction headroom
- Monitor disk usage with Prometheus metrics

## Common Issues & Symptoms

### Slow Compaction

**Symptoms:**
- Growing disk usage
- Increasing read latency
- High CPU usage in background threads

**Solutions:**
```bash
# Increase background jobs
export PQPRIV_DB_MAX_BACKGROUND_JOBS=16

# Reduce target file size for faster compaction
export PQPRIV_DB_TARGET_FILE_SIZE_MB=32
```

### High Memory Usage

**Symptoms:**
- OOM kills
- Swap thrashing
- Slow queries

**Solutions:**
```bash
# Reduce cache sizes
export PQPRIV_DB_WRITE_BUFFER_MB=64
export PQPRIV_DB_BLOCK_CACHE_MB=128
```

### WAL Growth

**Symptoms:**
- WAL directory growing unbounded
- Disk space exhaustion

**Solutions:**
- Ensure WAL sync is enabled (`wal_enabled=true`)
- Check that node is committing transactions properly
- Verify disk write performance (may be I/O bottleneck)

### Cache Thrashing

**Symptoms:**
- High read latency
- Frequent disk reads
- Low cache hit rate

**Solutions:**
```bash
# Increase block cache
export PQPRIV_DB_BLOCK_CACHE_MB=1024

# Increase readahead for sequential scans
export PQPRIV_DB_READAHEAD_MB=8
```

## Metrics & Monitoring

RocksDB exposes Prometheus metrics for monitoring:

```bash
curl -s localhost:9090/metrics | grep node_db
```

**Key Metrics:**
- `node_db_size_bytes`: Total database size on disk
- `node_db_write_batch_ms_*`: Write latency histogram
- `node_db_compaction_jobs`: Active compaction threads
- `node_db_wal_synced_total`: WAL sync operations

**Alerting Thresholds:**
- `node_db_size_bytes` growing >10% per day
- `node_db_write_batch_ms_bucket{le="100"}` <95% (p95 >100ms)
- Disk usage >80%

## Benchmarking

### Write Throughput

```bash
# Run devnet with mining to generate blocks
./target/release/node --devnet --mine --target-blocks 10000 \
  --db.write-buffer-mb 256 --db.block-cache-mb 512

# Monitor write performance
watch -n 1 'curl -s localhost:9090/metrics | grep node_db_write_batch'
```

### Read Latency

```bash
# Query historical blocks repeatedly
for i in {1..1000}; do
  curl -s localhost:9090/rpc/block/$i > /dev/null
done
```

### Compaction Performance

```bash
# Force heavy writes then monitor compaction
./target/release/node --devnet --mine --target-blocks 50000 \
  --db.max-background-jobs 16
  
# Check compaction stats (if RocksDB property exposed)
# TODO: Add compaction metrics endpoint
```

## Production Checklist

Before deploying to production:

- [ ] WAL enabled (`wal_enabled=true`)
- [ ] Compression set to `zstd`
- [ ] Block cache ≥512 MB
- [ ] Background jobs ≥8
- [ ] Mounted with `noatime` (Linux)
- [ ] File descriptor limit ≥65536
- [ ] SSD/NVMe storage (not HDD)
- [ ] Monitoring configured (Prometheus)
- [ ] Backup strategy tested (snapshots)
- [ ] Disk space alerts configured

## References

- [RocksDB Tuning Guide](https://github.com/facebook/rocksdb/wiki/RocksDB-Tuning-Guide)
- [RocksDB FAQ](https://github.com/facebook/rocksdb/wiki/RocksDB-FAQ)
- [PQ-PRIV Storage Schema](../../spec/storage.md)
