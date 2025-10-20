//! Background task for updating storage metrics.
//!
//! Updates SST size (from RocksDB property), WAL size (from filesystem scan),
//! and total directory size (from filesystem scan) every 15 seconds.
//!
//! This prevents /metrics endpoint from blocking on disk I/O operations.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::Mutex;
use tokio::time::interval;
use tracing::{debug, error, warn};

use crate::metrics::StorageMetrics;
use crate::state::ChainState;

/// Periodically update storage metrics (SST/WAL/dir sizes).
///
/// # Arguments
/// - `data_dir`: Path to the database directory
/// - `chain`: Chain state (to access RocksDB store)
/// - `metrics`: Metrics collector to update
///
/// # Interval
/// Updates every 15 seconds to balance freshness vs overhead.
pub async fn run_storage_metrics_task(
    data_dir: impl AsRef<Path>,
    chain: Arc<Mutex<ChainState>>,
    metrics: Arc<StorageMetrics>,
) {
    let data_dir = data_dir.as_ref().to_path_buf();
    let mut ticker = interval(Duration::from_secs(15));

    loop {
        ticker.tick().await;

        // 1. SST size from RocksDB property (fast, in-memory)
        {
            let guard = chain.lock();
            let store = guard.store();
            match store.total_db_size() {
                Ok(sst_size) => {
                    debug!("SST size: {} bytes ({} MB)", sst_size, sst_size / 1024 / 1024);
                    metrics.set_sst_size_bytes(sst_size);
                }
                Err(e) => {
                    error!("Failed to read SST size from RocksDB: {}", e);
                }
            }
        }

        // 2. WAL size from filesystem scan (medium cost)
        match calculate_wal_size(&data_dir) {
            Ok(wal_size) => {
                debug!("WAL size: {} bytes ({} MB)", wal_size, wal_size / 1024 / 1024);
                metrics.set_wal_size_bytes(wal_size);
            }
            Err(e) => {
                warn!("Failed to calculate WAL size: {}", e);
            }
        }

        // 3. Total directory size from filesystem scan (highest cost)
        match calculate_dir_size(&data_dir) {
            Ok(dir_size) => {
                debug!("Total DB dir size: {} bytes ({} MB)", dir_size, dir_size / 1024 / 1024);
                metrics.set_dir_size_bytes(dir_size);
            }
            Err(e) => {
                error!("Failed to calculate total directory size: {}", e);
            }
        }
    }
}

/// Calculate size of WAL files only.
fn calculate_wal_size(data_dir: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;

    if !data_dir.is_dir() {
        return Ok(0);
    }

    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // WAL files have format: <number>.log (e.g., 000003.log)
        if name_str.ends_with(".log") && entry.metadata()?.is_file() {
            total += entry.metadata()?.len();
        }
    }

    Ok(total)
}

/// Recursively calculate directory size in bytes.
fn calculate_dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;

            if metadata.is_dir() {
                total += calculate_dir_size(&entry.path())?;
            } else {
                total += metadata.len();
            }
        }
    } else if path.is_file() {
        total = path.metadata()?.len();
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_calculate_dir_size() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        // Create some test files
        let mut file1 = File::create(path.join("file1.txt")).unwrap();
        file1.write_all(b"hello").unwrap(); // 5 bytes
        drop(file1); // Ensure file is closed and flushed

        let mut file2 = File::create(path.join("file2.txt")).unwrap();
        file2.write_all(b"world!!!").unwrap(); // 8 bytes
        drop(file2);

        // Create subdirectory with file
        std::fs::create_dir(path.join("subdir")).unwrap();
        let mut file3 = File::create(path.join("subdir/file3.txt")).unwrap();
        file3.write_all(b"test").unwrap(); // 4 bytes
        drop(file3);

        let total = calculate_dir_size(path).unwrap();
        assert_eq!(total, 5 + 8 + 4); // 17 bytes
    }

    #[test]
    fn test_calculate_wal_size() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        // Create WAL files
        let mut wal1 = File::create(path.join("000001.log")).unwrap();
        wal1.write_all(b"wal data 1").unwrap(); // 10 bytes
        drop(wal1);

        let mut wal2 = File::create(path.join("000002.log")).unwrap();
        wal2.write_all(b"wal data 2 longer").unwrap(); // 17 bytes
        drop(wal2);

        // Create non-WAL files (should be ignored)
        let mut other = File::create(path.join("CURRENT")).unwrap();
        other.write_all(b"manifest").unwrap(); // 8 bytes (ignored)
        drop(other);

        let mut sst = File::create(path.join("000003.sst")).unwrap();
        sst.write_all(b"sst data").unwrap(); // 8 bytes (ignored)
        drop(sst);

        let total = calculate_wal_size(path).unwrap();
        assert_eq!(total, 10 + 17); // Only .log files = 27 bytes
    }
}
