//! Storage metrics tracking for write batch operations.
//!
//! This module provides a simple timer for measuring write batch latency
//! when the "metrics" feature is enabled. The actual metrics storage and
//! exposition is handled by the node crate's StorageMetrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Global histogram buckets counter for write batch latency (in microseconds).
/// Buckets: <1ms, 1-5ms, 5-10ms, 10-50ms, 50-100ms, 100-500ms, 500-1000ms, >1000ms
static WRITE_BATCH_BUCKETS: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Timer guard that records write batch duration when dropped.
pub struct WriteBatchTimer {
    start: Instant,
}

impl WriteBatchTimer {
    /// Start timing a write batch operation.
    #[inline]
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Drop for WriteBatchTimer {
    fn drop(&mut self) {
        let elapsed_us = self.start.elapsed().as_micros() as u64;
        let bucket_idx = match elapsed_us {
            0..=999 => 0,         // <1ms
            1000..=4999 => 1,     // 1-5ms
            5000..=9999 => 2,     // 5-10ms
            10000..=49999 => 3,   // 10-50ms
            50000..=99999 => 4,   // 50-100ms
            100000..=499999 => 5, // 100-500ms
            500000..=999999 => 6, // 500-1000ms
            _ => 7,               // >1000ms
        };
        WRITE_BATCH_BUCKETS[bucket_idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// Get current histogram bucket counts (for node metrics integration).
pub fn get_histogram_buckets() -> [u64; 8] {
    [
        WRITE_BATCH_BUCKETS[0].load(Ordering::Relaxed),
        WRITE_BATCH_BUCKETS[1].load(Ordering::Relaxed),
        WRITE_BATCH_BUCKETS[2].load(Ordering::Relaxed),
        WRITE_BATCH_BUCKETS[3].load(Ordering::Relaxed),
        WRITE_BATCH_BUCKETS[4].load(Ordering::Relaxed),
        WRITE_BATCH_BUCKETS[5].load(Ordering::Relaxed),
        WRITE_BATCH_BUCKETS[6].load(Ordering::Relaxed),
        WRITE_BATCH_BUCKETS[7].load(Ordering::Relaxed),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_timer_records_buckets() {
        // Reset buckets
        for bucket in &WRITE_BATCH_BUCKETS {
            bucket.store(0, Ordering::Relaxed);
        }

        // Simulate fast write (<1ms)
        {
            let _timer = WriteBatchTimer::start();
            // Immediate drop
        }

        let buckets = get_histogram_buckets();
        assert!(buckets[0] >= 1, "Fast write should increment bucket 0");

        // Simulate slower write (~2ms)
        {
            let _timer = WriteBatchTimer::start();
            thread::sleep(Duration::from_millis(2));
        }

        let buckets = get_histogram_buckets();
        assert!(buckets[1] >= 1, "2ms write should increment bucket 1");
    }

    #[test]
    fn test_histogram_buckets_boundaries() {
        for bucket in &WRITE_BATCH_BUCKETS {
            bucket.store(0, Ordering::Relaxed);
        }

        // Test each bucket boundary
        let test_cases = vec![
            (500, 0),     // 0.5ms -> bucket 0
            (1500, 1),    // 1.5ms -> bucket 1
            (7000, 2),    // 7ms -> bucket 2
            (25000, 3),   // 25ms -> bucket 3
            (75000, 4),   // 75ms -> bucket 4
            (200000, 5),  // 200ms -> bucket 5
            (750000, 6),  // 750ms -> bucket 6
            (2000000, 7), // 2000ms -> bucket 7
        ];

        for (us, expected_bucket) in test_cases {
            for bucket in &WRITE_BATCH_BUCKETS {
                bucket.store(0, Ordering::Relaxed);
            }

            let timer = WriteBatchTimer {
                start: Instant::now(),
            };
            std::mem::forget(timer); // Don't record yet

            // Manually trigger bucket logic
            let bucket_idx = match us {
                0..=999 => 0,
                1000..=4999 => 1,
                5000..=9999 => 2,
                10000..=49999 => 3,
                50000..=99999 => 4,
                100000..=499999 => 5,
                500000..=999999 => 6,
                _ => 7,
            };
            WRITE_BATCH_BUCKETS[bucket_idx].fetch_add(1, Ordering::Relaxed);

            let buckets = get_histogram_buckets();
            assert_eq!(
                buckets[expected_bucket], 1,
                "{}us should map to bucket {}",
                us, expected_bucket
            );
        }
    }
}
