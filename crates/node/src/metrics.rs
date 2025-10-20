//! Prometheus metrics for PQ-PRIV node.
//!
//! Exposes storage, network, and consensus metrics.

use parking_lot::Mutex;
use std::sync::Arc;

/// Storage metrics collector with separate SST, WAL, and directory size metrics.
///
/// These metrics are updated by a background task every 15-30 seconds to avoid
/// blocking /metrics endpoint requests with disk I/O operations.
#[derive(Clone)]
pub struct StorageMetrics {
    /// SST file size in bytes (from RocksDB property).
    sst_size_bytes: Arc<Mutex<u64>>,
    /// WAL file size in bytes (from filesystem scan).
    wal_size_bytes: Arc<Mutex<u64>>,
    /// Total directory size in bytes (from filesystem scan).
    dir_size_bytes: Arc<Mutex<u64>>,
}

impl StorageMetrics {
    pub fn new() -> Self {
        Self {
            sst_size_bytes: Arc::new(Mutex::new(0)),
            wal_size_bytes: Arc::new(Mutex::new(0)),
            dir_size_bytes: Arc::new(Mutex::new(0)),
        }
    }

    /// Update SST file size gauge (from RocksDB property).
    pub fn set_sst_size_bytes(&self, size: u64) {
        *self.sst_size_bytes.lock() = size;
    }

    /// Update WAL file size gauge (from filesystem scan).
    pub fn set_wal_size_bytes(&self, size: u64) {
        *self.wal_size_bytes.lock() = size;
    }

    /// Update total directory size gauge (from filesystem scan).
    pub fn set_dir_size_bytes(&self, size: u64) {
        *self.dir_size_bytes.lock() = size;
    }

    /// Generate Prometheus exposition format output.
    ///
    /// This method reads cached values updated by the background task,
    /// so it does NOT perform any blocking disk I/O.
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // SST file size (from RocksDB property)
        let sst_size = *self.sst_size_bytes.lock();
        output.push_str("# HELP node_db_sst_bytes Size of SST files from RocksDB property\n");
        output.push_str("# TYPE node_db_sst_bytes gauge\n");
        output.push_str(&format!("node_db_sst_bytes {}\n", sst_size));

        // WAL file size (from filesystem scan)
        let wal_size = *self.wal_size_bytes.lock();
        output.push_str("# HELP node_db_wal_bytes Size of WAL files from filesystem scan\n");
        output.push_str("# TYPE node_db_wal_bytes gauge\n");
        output.push_str(&format!("node_db_wal_bytes {}\n", wal_size));

        // Total directory size (from filesystem scan)
        let dir_size = *self.dir_size_bytes.lock();
        output.push_str("# HELP node_db_dir_bytes Total database directory size including all files\n");
        output.push_str("# TYPE node_db_dir_bytes gauge\n");
        output.push_str(&format!("node_db_dir_bytes {}\n", dir_size));

        // Write batch histogram - read from storage crate
        {
            let storage_buckets = storage::metrics::get_histogram_buckets();
            let count: u64 = storage_buckets.iter().sum();

            output.push_str(
                "# HELP node_db_write_batch_ms Write batch operation duration in milliseconds\n",
            );
            output.push_str("# TYPE node_db_write_batch_ms histogram\n");

            let bucket_bounds = [1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0];
            let mut cumulative = 0u64;

            for (i, &bound) in bucket_bounds.iter().enumerate() {
                cumulative += storage_buckets[i];
                output.push_str(&format!(
                    "node_db_write_batch_ms_bucket{{le=\"{}\"}} {}\n",
                    bound, cumulative
                ));
            }

            // +inf bucket
            cumulative += storage_buckets[7];
            output.push_str(&format!(
                "node_db_write_batch_ms_bucket{{le=\"+Inf\"}} {}\n",
                cumulative
            ));

            output.push_str(&format!("node_db_write_batch_ms_count {}\n", count));

            // Calculate sum (approximate from bucket midpoints)
            let sum_ms = (storage_buckets[0] as f64 * 0.5)
                + (storage_buckets[1] as f64 * 3.0)
                + (storage_buckets[2] as f64 * 7.5)
                + (storage_buckets[3] as f64 * 30.0)
                + (storage_buckets[4] as f64 * 75.0)
                + (storage_buckets[5] as f64 * 300.0)
                + (storage_buckets[6] as f64 * 750.0)
                + (storage_buckets[7] as f64 * 1500.0);
            output.push_str(&format!("node_db_write_batch_ms_sum {:.2}\n", sum_ms));
        }

        // WAL sync counter
        // Note: Each write batch commit triggers a WAL sync, so we use the histogram count
        let wal_synced = {
            let storage_buckets = storage::metrics::get_histogram_buckets();
            storage_buckets.iter().sum::<u64>()
        };
        output.push_str(
            "# HELP node_db_wal_synced_total Number of WAL sync operations (write batch commits)\n",
        );
        output.push_str("# TYPE node_db_wal_synced_total counter\n");
        output.push_str(&format!("node_db_wal_synced_total {}\n", wal_synced));

        output
    }
}

impl Default for StorageMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_size_gauges() {
        let metrics = StorageMetrics::new();
        metrics.set_sst_size_bytes(1024 * 1024 * 400); // 400 MB SST
        metrics.set_wal_size_bytes(1024 * 1024 * 50);  // 50 MB WAL
        metrics.set_dir_size_bytes(1024 * 1024 * 500); // 500 MB total

        let output = metrics.to_prometheus();
        assert!(output.contains("node_db_sst_bytes 419430400"));
        assert!(output.contains("node_db_wal_bytes 52428800"));
        assert!(output.contains("node_db_dir_bytes 524288000"));
    }

    #[test]
    fn test_write_batch_histogram_integration() {
        {
            let metrics = StorageMetrics::new();

            // Histogram data comes from storage crate, just test format
            let output = metrics.to_prometheus();
            assert!(output.contains("# TYPE node_db_write_batch_ms histogram"));
            assert!(output.contains("node_db_write_batch_ms_bucket{le=\"1\"}"));
        }
    }

    #[test]
    fn test_wal_counter() {
        // WAL counter is derived from write_batch histogram count
        // This test verifies the metric appears in output
        let metrics = StorageMetrics::new();

        let output = metrics.to_prometheus();
        assert!(output.contains("node_db_wal_synced_total"));
        assert!(output.contains("# TYPE node_db_wal_synced_total counter"));
    }
}
