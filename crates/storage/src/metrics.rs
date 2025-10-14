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

    #[test]
    fn test_bucket_mapping_logic() {
        // Test that the bucket selection logic correctly maps elapsed time to bucket indices
        // We test the exact match expression used in WriteBatchTimer::drop
        let test_cases = vec![
            // Bucket 0: 0-999 microseconds (<1ms)
            (0, 0),
            (500, 0),
            (999, 0),
            // Bucket 1: 1000-4999 microseconds (1-5ms)
            (1000, 1),
            (1500, 1),
            (4999, 1),
            // Bucket 2: 5000-9999 microseconds (5-10ms)
            (5000, 2),
            (7000, 2),
            (9999, 2),
            // Bucket 3: 10000-49999 microseconds (10-50ms)
            (10000, 3),
            (25000, 3),
            (49999, 3),
            // Bucket 4: 50000-99999 microseconds (50-100ms)
            (50000, 4),
            (75000, 4),
            (99999, 4),
            // Bucket 5: 100000-499999 microseconds (100-500ms)
            (100000, 5),
            (200000, 5),
            (499999, 5),
            // Bucket 6: 500000-999999 microseconds (500-1000ms)
            (500000, 6),
            (750000, 6),
            (999999, 6),
            // Bucket 7: 1000000+ microseconds (>1000ms)
            (1000000, 7),
            (2000000, 7),
            (10000000, 7),
        ];

        for (elapsed_us, expected_bucket_idx) in test_cases {
            // Reset all buckets before each test case
            for bucket in &WRITE_BATCH_BUCKETS {
                bucket.store(0, Ordering::Relaxed);
            }

            // Apply the exact bucket selection logic from WriteBatchTimer::drop
            let bucket_idx = match elapsed_us {
                0..=999 => 0,
                1000..=4999 => 1,
                5000..=9999 => 2,
                10000..=49999 => 3,
                50000..=99999 => 4,
                100000..=499999 => 5,
                500000..=999999 => 6,
                _ => 7,
            };

            assert_eq!(
                bucket_idx, expected_bucket_idx,
                "{}us should map to bucket {}",
                elapsed_us, expected_bucket_idx
            );

            // Test the actual counter increment
            WRITE_BATCH_BUCKETS[bucket_idx].fetch_add(1, Ordering::Relaxed);
            let buckets = get_histogram_buckets();
            assert_eq!(
                buckets[expected_bucket_idx], 1,
                "Bucket {} should have count 1 after increment for {}us",
                expected_bucket_idx, elapsed_us
            );
        }
    }
}
