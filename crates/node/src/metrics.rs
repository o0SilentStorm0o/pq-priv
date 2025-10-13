//! Prometheus metrics for PQ-PRIV node.
//!
//! Exposes storage, network, and consensus metrics.

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;

/// Storage metrics collector.
#[derive(Clone)]
pub struct StorageMetrics {
    /// Total database size in bytes (gauge).
    db_size_bytes: Arc<Mutex<u64>>,
    
    /// Write batch latency samples (histogram buckets).
    /// Buckets: [1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1000ms, +inf]
    write_batch_buckets: Arc<Mutex<[u64; 8]>>,
    
    /// Total write batch operations count.
    write_batch_count: Arc<Mutex<u64>>,
    
    /// Total write batch duration sum (milliseconds).
    write_batch_sum_ms: Arc<Mutex<f64>>,
    
    /// WAL sync operations counter.
    wal_synced_total: Arc<Mutex<u64>>,
}

impl StorageMetrics {
    pub fn new() -> Self {
        Self {
            db_size_bytes: Arc::new(Mutex::new(0)),
            write_batch_buckets: Arc::new(Mutex::new([0; 8])),
            write_batch_count: Arc::new(Mutex::new(0)),
            write_batch_sum_ms: Arc::new(Mutex::new(0.0)),
            wal_synced_total: Arc::new(Mutex::new(0)),
        }
    }

    /// Update database size gauge.
    pub fn set_db_size_bytes(&self, size: u64) {
        *self.db_size_bytes.lock() = size;
    }

    /// Record a write batch operation with duration.
    pub fn record_write_batch(&self, duration_ms: f64) {
        let mut buckets = self.write_batch_buckets.lock();
        let mut count = self.write_batch_count.lock();
        let mut sum = self.write_batch_sum_ms.lock();

        *count += 1;
        *sum += duration_ms;

        // Increment appropriate bucket
        // Buckets: 1, 5, 10, 50, 100, 500, 1000, +inf
        if duration_ms <= 1.0 {
            buckets[0] += 1;
        } else if duration_ms <= 5.0 {
            buckets[1] += 1;
        } else if duration_ms <= 10.0 {
            buckets[2] += 1;
        } else if duration_ms <= 50.0 {
            buckets[3] += 1;
        } else if duration_ms <= 100.0 {
            buckets[4] += 1;
        } else if duration_ms <= 500.0 {
            buckets[5] += 1;
        } else if duration_ms <= 1000.0 {
            buckets[6] += 1;
        } else {
            buckets[7] += 1;
        }
    }

    /// Increment WAL sync counter.
    pub fn increment_wal_synced(&self) {
        *self.wal_synced_total.lock() += 1;
    }

    /// Generate Prometheus exposition format output.
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Database size gauge
        let db_size = *self.db_size_bytes.lock();
        output.push_str("# HELP node_db_size_bytes Total database size on disk\n");
        output.push_str("# TYPE node_db_size_bytes gauge\n");
        output.push_str(&format!("node_db_size_bytes {}\n", db_size));

        // Write batch histogram
        let buckets = *self.write_batch_buckets.lock();
        let count = *self.write_batch_count.lock();
        let sum = *self.write_batch_sum_ms.lock();

        output.push_str("# HELP node_db_write_batch_ms Write batch operation duration in milliseconds\n");
        output.push_str("# TYPE node_db_write_batch_ms histogram\n");

        let bucket_bounds = [1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0];
        let mut cumulative = 0u64;

        for (i, &bound) in bucket_bounds.iter().enumerate() {
            cumulative += buckets[i];
            output.push_str(&format!(
                "node_db_write_batch_ms_bucket{{le=\"{}\"}} {}\n",
                bound, cumulative
            ));
        }

        // +inf bucket
        cumulative += buckets[7];
        output.push_str(&format!(
            "node_db_write_batch_ms_bucket{{le=\"+Inf\"}} {}\n",
            cumulative
        ));

        output.push_str(&format!("node_db_write_batch_ms_count {}\n", count));
        output.push_str(&format!("node_db_write_batch_ms_sum {}\n", sum));

        // WAL sync counter
        let wal_synced = *self.wal_synced_total.lock();
        output.push_str("# HELP node_db_wal_synced_total Number of WAL sync operations\n");
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

/// Helper to measure write batch duration.
pub struct WriteBatchTimer {
    start: Instant,
    metrics: StorageMetrics,
}

impl WriteBatchTimer {
    pub fn new(metrics: StorageMetrics) -> Self {
        Self {
            start: Instant::now(),
            metrics,
        }
    }

    /// Finish timing and record the duration.
    pub fn finish(self) {
        let duration = self.start.elapsed();
        let duration_ms = duration.as_secs_f64() * 1000.0;
        self.metrics.record_write_batch(duration_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_size_gauge() {
        let metrics = StorageMetrics::new();
        metrics.set_db_size_bytes(1024 * 1024 * 500); // 500 MB

        let output = metrics.to_prometheus();
        assert!(output.contains("node_db_size_bytes 524288000"));
    }

    #[test]
    fn test_write_batch_histogram() {
        let metrics = StorageMetrics::new();
        
        // Record various durations
        metrics.record_write_batch(0.5);   // bucket 1ms
        metrics.record_write_batch(3.0);   // bucket 5ms
        metrics.record_write_batch(8.0);   // bucket 10ms
        metrics.record_write_batch(45.0);  // bucket 50ms
        metrics.record_write_batch(150.0); // bucket 500ms

        let output = metrics.to_prometheus();
        assert!(output.contains("node_db_write_batch_ms_bucket{le=\"1\"} 1"));
        assert!(output.contains("node_db_write_batch_ms_bucket{le=\"5\"} 2"));
        assert!(output.contains("node_db_write_batch_ms_bucket{le=\"10\"} 3"));
        assert!(output.contains("node_db_write_batch_ms_count 5"));
    }

    #[test]
    fn test_wal_counter() {
        let metrics = StorageMetrics::new();
        
        metrics.increment_wal_synced();
        metrics.increment_wal_synced();
        metrics.increment_wal_synced();

        let output = metrics.to_prometheus();
        assert!(output.contains("node_db_wal_synced_total 3"));
    }

    #[test]
    fn test_timer() {
        let metrics = StorageMetrics::new();
        let timer = WriteBatchTimer::new(metrics.clone());
        
        std::thread::sleep(std::time::Duration::from_millis(10));
        timer.finish();

        let output = metrics.to_prometheus();
        assert!(output.contains("node_db_write_batch_ms_count 1"));
    }
}
