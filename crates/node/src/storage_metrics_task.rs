//! Background task for updating storage metrics.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error};

use crate::metrics::StorageMetrics;

/// Periodically update storage metrics (DB size, etc.).
pub async fn run_storage_metrics_task(
    data_dir: impl AsRef<Path>,
    metrics: Arc<StorageMetrics>,
) {
    let data_dir = data_dir.as_ref().to_path_buf();
    let mut ticker = interval(Duration::from_secs(30));

    loop {
        ticker.tick().await;

        // Calculate directory size
        match calculate_dir_size(&data_dir) {
            Ok(size) => {
                debug!("DB size: {} bytes ({} MB)", size, size / 1024 / 1024);
                metrics.set_db_size_bytes(size);
            }
            Err(e) => {
                error!("Failed to calculate DB size: {}", e);
            }
        }
    }
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

        let mut file2 = File::create(path.join("file2.txt")).unwrap();
        file2.write_all(b"world!!!").unwrap(); // 8 bytes

        // Create subdirectory with file
        std::fs::create_dir(path.join("subdir")).unwrap();
        let mut file3 = File::create(path.join("subdir/file3.txt")).unwrap();
        file3.write_all(b"test").unwrap(); // 4 bytes

        let total = calculate_dir_size(path).unwrap();
        assert_eq!(total, 5 + 8 + 4); // 17 bytes
    }
}
