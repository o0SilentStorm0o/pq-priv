//! Prometheus metrics for PQ-PRIV node.
//!
//! Exposes storage, network, and consensus metrics.

use parking_lot::Mutex;
use std::sync::Arc;

/// Storage metrics collector with separate SST, WAL, and directory size metrics.
///
/// These metrics are updated by a background task every 15-30 seconds to avoid
/// blocking /metrics endpoint requests with disk I/O operations.
///
/// Also includes snapshot/restore metrics.
#[derive(Clone)]
pub struct StorageMetrics {
    /// SST file size in bytes (from RocksDB property).
    sst_size_bytes: Arc<Mutex<u64>>,
    /// WAL file size in bytes (from filesystem scan).
    wal_size_bytes: Arc<Mutex<u64>>,
    /// Total directory size in bytes (from filesystem scan).
    dir_size_bytes: Arc<Mutex<u64>>,
    /// Snapshot creation counter.
    snapshot_count_total: Arc<Mutex<u64>>,
    /// Snapshot creation failures counter.
    snapshot_failures_total: Arc<Mutex<u64>>,
    /// Last snapshot duration in milliseconds (gauge).
    snapshot_last_duration_ms: Arc<Mutex<u64>>,
    /// Last snapshot height (gauge).
    snapshot_last_height: Arc<Mutex<u64>>,
    /// Snapshot restore counter.
    restore_count_total: Arc<Mutex<u64>>,
    /// Snapshot restore failures counter.
    restore_failures_total: Arc<Mutex<u64>>,
}

impl StorageMetrics {
    pub fn new() -> Self {
        Self {
            sst_size_bytes: Arc::new(Mutex::new(0)),
            wal_size_bytes: Arc::new(Mutex::new(0)),
            dir_size_bytes: Arc::new(Mutex::new(0)),
            snapshot_count_total: Arc::new(Mutex::new(0)),
            snapshot_failures_total: Arc::new(Mutex::new(0)),
            snapshot_last_duration_ms: Arc::new(Mutex::new(0)),
            snapshot_last_height: Arc::new(Mutex::new(0)),
            restore_count_total: Arc::new(Mutex::new(0)),
            restore_failures_total: Arc::new(Mutex::new(0)),
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

    /// Increment snapshot creation counter and update last snapshot metadata.
    pub fn record_snapshot_success(&self, height: u64, duration_ms: u64) {
        *self.snapshot_count_total.lock() += 1;
        *self.snapshot_last_height.lock() = height;
        *self.snapshot_last_duration_ms.lock() = duration_ms;
    }

    /// Increment snapshot failure counter.
    pub fn record_snapshot_failure(&self) {
        *self.snapshot_failures_total.lock() += 1;
    }

    /// Increment restore counter.
    pub fn record_restore_success(&self) {
        *self.restore_count_total.lock() += 1;
    }

    /// Increment restore failure counter.
    pub fn record_restore_failure(&self) {
        *self.restore_failures_total.lock() += 1;
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
        output.push_str(
            "# HELP node_db_dir_bytes Total database directory size including all files\n",
        );
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

        // Snapshot metrics
        let snapshot_count = *self.snapshot_count_total.lock();
        let snapshot_failures = *self.snapshot_failures_total.lock();
        let snapshot_duration = *self.snapshot_last_duration_ms.lock();
        let snapshot_height = *self.snapshot_last_height.lock();
        let restore_count = *self.restore_count_total.lock();
        let restore_failures = *self.restore_failures_total.lock();

        output
            .push_str("# HELP node_snapshot_count_total Number of successful snapshot creations\n");
        output.push_str("# TYPE node_snapshot_count_total counter\n");
        output.push_str(&format!("node_snapshot_count_total {}\n", snapshot_count));

        output
            .push_str("# HELP node_snapshot_failures_total Number of failed snapshot creations\n");
        output.push_str("# TYPE node_snapshot_failures_total counter\n");
        output.push_str(&format!(
            "node_snapshot_failures_total {}\n",
            snapshot_failures
        ));

        output.push_str(
            "# HELP node_snapshot_last_duration_ms Duration of last snapshot creation in milliseconds\n",
        );
        output.push_str("# TYPE node_snapshot_last_duration_ms gauge\n");
        output.push_str(&format!(
            "node_snapshot_last_duration_ms {}\n",
            snapshot_duration
        ));

        output.push_str("# HELP node_snapshot_last_height Block height of last snapshot\n");
        output.push_str("# TYPE node_snapshot_last_height gauge\n");
        output.push_str(&format!("node_snapshot_last_height {}\n", snapshot_height));

        output.push_str("# HELP node_restore_count_total Number of successful snapshot restores\n");
        output.push_str("# TYPE node_restore_count_total counter\n");
        output.push_str(&format!("node_restore_count_total {}\n", restore_count));

        output.push_str("# HELP node_restore_failures_total Number of failed snapshot restores\n");
        output.push_str("# TYPE node_restore_failures_total counter\n");
        output.push_str(&format!(
            "node_restore_failures_total {}\n",
            restore_failures
        ));

        output
    }
}

impl Default for StorageMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Privacy metrics collector for confidential transaction validation.
///
/// Tracks range proof verification performance, failure rates, and commitment balance checks.
/// These metrics are critical for monitoring privacy feature adoption and detecting attacks.
#[derive(Clone)]
pub struct PrivacyMetrics {
    /// Range proof verification latency histogram (milliseconds).
    /// Buckets: [1, 5, 10, 50, 100, 500, 1000, +Inf] ms
    verify_latency_buckets: Arc<Mutex<[u64; 8]>>,
    /// Total number of range proof verifications (counter).
    verify_count_total: Arc<Mutex<u64>>,
    /// Total number of invalid range proofs rejected (counter).
    invalid_proofs_total: Arc<Mutex<u64>>,
    /// Total number of commitment balance failures (counter).
    balance_failures_total: Arc<Mutex<u64>>,
}

impl PrivacyMetrics {
    pub fn new() -> Self {
        Self {
            verify_latency_buckets: Arc::new(Mutex::new([0; 8])),
            verify_count_total: Arc::new(Mutex::new(0)),
            invalid_proofs_total: Arc::new(Mutex::new(0)),
            balance_failures_total: Arc::new(Mutex::new(0)),
        }
    }

    /// Record a successful range proof verification with duration.
    ///
    /// # Arguments
    /// * `duration_ms` - Verification duration in milliseconds
    pub fn record_verify_success(&self, duration_ms: u64) {
        *self.verify_count_total.lock() += 1;

        // Bucket boundaries: [1, 5, 10, 50, 100, 500, 1000, +Inf]
        let mut buckets = self.verify_latency_buckets.lock();
        let bucket_idx = match duration_ms {
            0..=1 => 0,
            2..=5 => 1,
            6..=10 => 2,
            11..=50 => 3,
            51..=100 => 4,
            101..=500 => 5,
            501..=1000 => 6,
            _ => 7, // +Inf
        };
        buckets[bucket_idx] += 1;
    }

    /// Record an invalid range proof rejection.
    pub fn record_invalid_proof(&self) {
        *self.invalid_proofs_total.lock() += 1;
    }

    /// Record a commitment balance verification failure.
    pub fn record_balance_failure(&self) {
        *self.balance_failures_total.lock() += 1;
    }

    /// Generate Prometheus exposition format output for privacy metrics.
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Range proof verification latency histogram
        {
            let buckets = *self.verify_latency_buckets.lock();
            let count: u64 = buckets.iter().sum();

            output.push_str(
                "# HELP pqpriv_range_proof_verify_ms Range proof verification duration in milliseconds\n",
            );
            output.push_str("# TYPE pqpriv_range_proof_verify_ms histogram\n");

            let bucket_bounds = [1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0];
            let mut cumulative = 0u64;

            for (i, &bound) in bucket_bounds.iter().enumerate() {
                cumulative += buckets[i];
                output.push_str(&format!(
                    "pqpriv_range_proof_verify_ms_bucket{{le=\"{}\"}} {}\n",
                    bound, cumulative
                ));
            }

            // +Inf bucket
            cumulative += buckets[7];
            output.push_str(&format!(
                "pqpriv_range_proof_verify_ms_bucket{{le=\"+Inf\"}} {}\n",
                cumulative
            ));

            output.push_str(&format!("pqpriv_range_proof_verify_ms_count {}\n", count));

            // Calculate sum (approximate from bucket midpoints)
            let sum_ms = (buckets[0] as f64 * 0.5)
                + (buckets[1] as f64 * 3.0)
                + (buckets[2] as f64 * 7.5)
                + (buckets[3] as f64 * 30.0)
                + (buckets[4] as f64 * 75.0)
                + (buckets[5] as f64 * 300.0)
                + (buckets[6] as f64 * 750.0)
                + (buckets[7] as f64 * 1500.0);
            output.push_str(&format!("pqpriv_range_proof_verify_ms_sum {:.2}\n", sum_ms));
        }

        // Range proof verification counter
        let verify_count = *self.verify_count_total.lock();
        output.push_str(
            "# HELP pqpriv_range_proof_verify_count Total number of range proof verifications\n",
        );
        output.push_str("# TYPE pqpriv_range_proof_verify_count counter\n");
        output.push_str(&format!("pqpriv_range_proof_verify_count {}\n", verify_count));

        // Invalid proof counter
        let invalid_count = *self.invalid_proofs_total.lock();
        output.push_str(
            "# HELP pqpriv_range_proof_invalid_total Number of invalid range proofs rejected\n",
        );
        output.push_str("# TYPE pqpriv_range_proof_invalid_total counter\n");
        output.push_str(&format!(
            "pqpriv_range_proof_invalid_total {}\n",
            invalid_count
        ));

        // Balance failure counter
        let balance_failures = *self.balance_failures_total.lock();
        output.push_str(
            "# HELP pqpriv_commitment_balance_fail_total Number of commitment balance verification failures\n",
        );
        output.push_str("# TYPE pqpriv_commitment_balance_fail_total counter\n");
        output.push_str(&format!(
            "pqpriv_commitment_balance_fail_total {}\n",
            balance_failures
        ));

        output
    }
}

impl Default for PrivacyMetrics {
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
        metrics.set_wal_size_bytes(1024 * 1024 * 50); // 50 MB WAL
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

    #[test]
    fn test_privacy_metrics_verify_success() {
        let metrics = PrivacyMetrics::new();

        // Record verifications in different latency buckets
        metrics.record_verify_success(1); // Bucket 0 (0-1ms)
        metrics.record_verify_success(3); // Bucket 1 (2-5ms)
        metrics.record_verify_success(7); // Bucket 2 (6-10ms)
        metrics.record_verify_success(25); // Bucket 3 (11-50ms)
        metrics.record_verify_success(75); // Bucket 4 (51-100ms)
        metrics.record_verify_success(200); // Bucket 5 (101-500ms)
        metrics.record_verify_success(800); // Bucket 6 (501-1000ms)
        metrics.record_verify_success(1500); // Bucket 7 (+Inf)

        let output = metrics.to_prometheus();

        // Verify histogram buckets (cumulative)
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"1\"} 1"));
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"5\"} 2"));
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"10\"} 3"));
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"50\"} 4"));
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"100\"} 5"));
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"500\"} 6"));
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"1000\"} 7"));
        assert!(output.contains("pqpriv_range_proof_verify_ms_bucket{le=\"+Inf\"} 8"));

        // Verify count
        assert!(output.contains("pqpriv_range_proof_verify_ms_count 8"));

        // Verify sum (approximate)
        assert!(output.contains("pqpriv_range_proof_verify_ms_sum"));

        // Verify counter
        assert!(output.contains("pqpriv_range_proof_verify_count 8"));
    }

    #[test]
    fn test_privacy_metrics_invalid_proofs() {
        let metrics = PrivacyMetrics::new();

        metrics.record_invalid_proof();
        metrics.record_invalid_proof();
        metrics.record_invalid_proof();

        let output = metrics.to_prometheus();
        assert!(output.contains("pqpriv_range_proof_invalid_total 3"));
        assert!(output.contains("# TYPE pqpriv_range_proof_invalid_total counter"));
    }

    #[test]
    fn test_privacy_metrics_balance_failures() {
        let metrics = PrivacyMetrics::new();

        metrics.record_balance_failure();
        metrics.record_balance_failure();

        let output = metrics.to_prometheus();
        assert!(output.contains("pqpriv_commitment_balance_fail_total 2"));
        assert!(output.contains("# TYPE pqpriv_commitment_balance_fail_total counter"));
    }

    #[test]
    fn test_privacy_metrics_full_output() {
        let metrics = PrivacyMetrics::new();

        // Mixed scenario
        metrics.record_verify_success(10);
        metrics.record_verify_success(50);
        metrics.record_invalid_proof();
        metrics.record_balance_failure();

        let output = metrics.to_prometheus();

        // Verify all metric types are present
        assert!(output.contains("# TYPE pqpriv_range_proof_verify_ms histogram"));
        assert!(output.contains("# TYPE pqpriv_range_proof_verify_count counter"));
        assert!(output.contains("# TYPE pqpriv_range_proof_invalid_total counter"));
        assert!(output.contains("# TYPE pqpriv_commitment_balance_fail_total counter"));

        // Verify HELP text
        assert!(output.contains("# HELP pqpriv_range_proof_verify_ms Range proof verification duration"));
        assert!(output.contains("# HELP pqpriv_range_proof_verify_count Total number of range proof verifications"));
        assert!(output.contains("# HELP pqpriv_range_proof_invalid_total Number of invalid range proofs rejected"));
        assert!(output.contains("# HELP pqpriv_commitment_balance_fail_total Number of commitment balance verification failures"));
    }
}
