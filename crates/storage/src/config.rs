//! Database tuning configuration for RocksDB.
//!
//! Provides configurable options for RocksDB tuning with sensible defaults
//! for development and production environments.

use serde::{Deserialize, Serialize};

/// Database tuning parameters for RocksDB.
///
/// All fields are optional to allow partial configuration.
/// Missing values fall back to sensible defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DbTuning {
    /// Maximum number of background jobs (compaction, flush).
    /// Default: 4 (conservative for CI/dev)
    pub max_background_jobs: Option<i32>,

    /// Write buffer size in MB (per column family).
    /// Default: 128 MB
    pub write_buffer_mb: Option<u64>,

    /// Target SST file size in MB.
    /// Default: 64 MB
    pub target_file_size_mb: Option<u64>,

    /// Enable dynamic level-based compaction.
    /// Default: true
    pub compaction_dynamic: Option<bool>,

    /// Compression algorithm: "zstd", "lz4", or "none".
    /// Default: "zstd"
    pub compression: Option<String>,

    /// Bytes per sync for SST writes (in MB).
    /// Default: 4 MB
    pub bytes_per_sync_mb: Option<u64>,

    /// Bytes per sync for WAL writes (in MB).
    /// Default: 4 MB
    pub wal_bytes_per_sync_mb: Option<u64>,

    /// Block cache size in MB.
    /// Default: 256 MB
    pub block_cache_mb: Option<u64>,

    /// Read-ahead size in MB for sequential reads.
    /// Default: 2 MB
    pub readahead_mb: Option<u64>,

    /// Enable pipelined writes for better write throughput.
    /// Default: true
    pub enable_pipelined_write: Option<bool>,

    /// Enable Write-Ahead Log (WAL).
    /// Default: true (production), false (debug)
    pub wal_enabled: Option<bool>,
}

impl Default for DbTuning {
    fn default() -> Self {
        Self {
            max_background_jobs: Some(4),
            write_buffer_mb: Some(128),
            target_file_size_mb: Some(64),
            compaction_dynamic: Some(true),
            compression: Some("zstd".into()),
            bytes_per_sync_mb: Some(4),
            wal_bytes_per_sync_mb: Some(4),
            block_cache_mb: Some(256),
            readahead_mb: Some(2),
            enable_pipelined_write: Some(true),
            wal_enabled: Some(true),
        }
    }
}

impl DbTuning {
    /// Create production-optimized tuning parameters.
    pub fn production() -> Self {
        Self {
            max_background_jobs: Some(8),
            write_buffer_mb: Some(256),
            target_file_size_mb: Some(128),
            compaction_dynamic: Some(true),
            compression: Some("zstd".into()),
            bytes_per_sync_mb: Some(8),
            wal_bytes_per_sync_mb: Some(8),
            block_cache_mb: Some(512),
            readahead_mb: Some(4),
            enable_pipelined_write: Some(true),
            wal_enabled: Some(true),
        }
    }

    /// Create development-optimized tuning parameters (faster, less I/O).
    pub fn development() -> Self {
        Self {
            max_background_jobs: Some(2),
            write_buffer_mb: Some(64),
            target_file_size_mb: Some(32),
            compaction_dynamic: Some(true),
            compression: Some("lz4".into()),
            bytes_per_sync_mb: Some(2),
            wal_bytes_per_sync_mb: Some(2),
            block_cache_mb: Some(128),
            readahead_mb: Some(1),
            enable_pipelined_write: Some(true),
            wal_enabled: Some(false), // Faster for dev
        }
    }

    /// Load from environment variables with `PQPRIV_DB_` prefix.
    ///
    /// Example: `PQPRIV_DB_WRITE_BUFFER_MB=256`
    ///
    /// This method applies validation and clamping to all values.
    pub fn from_env(mut self) -> Self {
        use std::env;

        if let Ok(val) = env::var("PQPRIV_DB_MAX_BACKGROUND_JOBS")
            && let Ok(num) = val.parse()
        {
            self.max_background_jobs = Some(num);
        }
        if let Ok(val) = env::var("PQPRIV_DB_WRITE_BUFFER_MB")
            && let Ok(num) = val.parse()
        {
            self.write_buffer_mb = Some(num);
        }
        if let Ok(val) = env::var("PQPRIV_DB_TARGET_FILE_SIZE_MB")
            && let Ok(num) = val.parse()
        {
            self.target_file_size_mb = Some(num);
        }
        if let Ok(val) = env::var("PQPRIV_DB_COMPRESSION") {
            self.compression = Some(val);
        }
        if let Ok(val) = env::var("PQPRIV_DB_BLOCK_CACHE_MB")
            && let Ok(num) = val.parse()
        {
            self.block_cache_mb = Some(num);
        }
        if let Ok(val) = env::var("PQPRIV_DB_WAL_ENABLED") {
            self.wal_enabled = Some(val == "true" || val == "1" || val == "on");
        }

        // Validate and clamp all values
        self.validate_and_clamp()
    }

    /// Validate and clamp all tuning parameters to safe ranges.
    ///
    /// This prevents misconfiguration from causing OOM, disk space issues,
    /// or other operational problems.
    pub fn validate_and_clamp(mut self) -> Self {
        use tracing::warn;

        // Write buffer: 16 MB to 2048 MB (2 GB)
        if let Some(val) = self.write_buffer_mb {
            if val < 16 {
                warn!("write_buffer_mb={} is too low, clamping to 16 MB", val);
                self.write_buffer_mb = Some(16);
            } else if val > 2048 {
                warn!("write_buffer_mb={} is too high, clamping to 2048 MB", val);
                self.write_buffer_mb = Some(2048);
            }
        }

        // Block cache: 64 MB to 16384 MB (16 GB)
        if let Some(val) = self.block_cache_mb {
            if val < 64 {
                warn!("block_cache_mb={} is too low, clamping to 64 MB", val);
                self.block_cache_mb = Some(64);
            } else if val > 16384 {
                warn!("block_cache_mb={} is too high, clamping to 16384 MB", val);
                self.block_cache_mb = Some(16384);
            }
        }

        // Compression: only zstd, lz4, or none
        if let Some(ref comp) = self.compression
            && comp != "zstd"
            && comp != "lz4"
            && comp != "none"
        {
            warn!("compression='{}' is invalid, using 'zstd'", comp);
            self.compression = Some("zstd".into());
        }

        // Target file size: 8 MB to 1024 MB (1 GB)
        if let Some(val) = self.target_file_size_mb {
            if val < 8 {
                warn!("target_file_size_mb={} is too low, clamping to 8 MB", val);
                self.target_file_size_mb = Some(8);
            } else if val > 1024 {
                warn!(
                    "target_file_size_mb={} is too high, clamping to 1024 MB",
                    val
                );
                self.target_file_size_mb = Some(1024);
            }
        }

        // Max background jobs: 1 to 16
        if let Some(val) = self.max_background_jobs {
            if val < 1 {
                warn!("max_background_jobs={} is too low, clamping to 1", val);
                self.max_background_jobs = Some(1);
            } else if val > 16 {
                warn!("max_background_jobs={} is too high, clamping to 16", val);
                self.max_background_jobs = Some(16);
            }
        }

        self
    }

    /// Get the effective value for max_background_jobs.
    pub fn max_background_jobs(&self) -> i32 {
        self.max_background_jobs.unwrap_or(4)
    }

    /// Get the effective value for write_buffer_mb.
    pub fn write_buffer_mb(&self) -> u64 {
        self.write_buffer_mb.unwrap_or(128)
    }

    /// Get the effective value for target_file_size_mb.
    pub fn target_file_size_mb(&self) -> u64 {
        self.target_file_size_mb.unwrap_or(64)
    }

    /// Get the effective value for compaction_dynamic.
    pub fn compaction_dynamic(&self) -> bool {
        self.compaction_dynamic.unwrap_or(true)
    }

    /// Get the effective compression algorithm.
    pub fn compression(&self) -> &str {
        self.compression.as_deref().unwrap_or("zstd")
    }

    /// Get the effective value for bytes_per_sync_mb.
    pub fn bytes_per_sync_mb(&self) -> u64 {
        self.bytes_per_sync_mb.unwrap_or(4)
    }

    /// Get the effective value for wal_bytes_per_sync_mb.
    pub fn wal_bytes_per_sync_mb(&self) -> u64 {
        self.wal_bytes_per_sync_mb.unwrap_or(4)
    }

    /// Get the effective value for block_cache_mb.
    pub fn block_cache_mb(&self) -> u64 {
        self.block_cache_mb.unwrap_or(256)
    }

    /// Get the effective value for readahead_mb.
    pub fn readahead_mb(&self) -> u64 {
        self.readahead_mb.unwrap_or(2)
    }

    /// Get the effective value for enable_pipelined_write.
    pub fn enable_pipelined_write(&self) -> bool {
        self.enable_pipelined_write.unwrap_or(true)
    }

    /// Get the effective value for wal_enabled.
    pub fn wal_enabled(&self) -> bool {
        self.wal_enabled.unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tuning() {
        let tuning = DbTuning::default();
        assert_eq!(tuning.max_background_jobs(), 4);
        assert_eq!(tuning.write_buffer_mb(), 128);
        assert_eq!(tuning.compression(), "zstd");
        assert!(tuning.wal_enabled());
    }

    #[test]
    fn test_production_tuning() {
        let tuning = DbTuning::production();
        assert_eq!(tuning.max_background_jobs(), 8);
        assert_eq!(tuning.write_buffer_mb(), 256);
        assert_eq!(tuning.block_cache_mb(), 512);
    }

    #[test]
    fn test_development_tuning() {
        let tuning = DbTuning::development();
        assert_eq!(tuning.max_background_jobs(), 2);
        assert_eq!(tuning.compression(), "lz4");
        assert!(!tuning.wal_enabled()); // WAL off for dev speed
    }

    #[test]
    fn test_clamp_write_buffer_too_low() {
        let tuning = DbTuning {
            write_buffer_mb: Some(5), // Below minimum
            ..Default::default()
        };
        let clamped = tuning.validate_and_clamp();
        assert_eq!(clamped.write_buffer_mb(), 16); // Clamped to minimum
    }

    #[test]
    fn test_clamp_write_buffer_too_high() {
        let tuning = DbTuning {
            write_buffer_mb: Some(3000), // Above maximum
            ..Default::default()
        };
        let clamped = tuning.validate_and_clamp();
        assert_eq!(clamped.write_buffer_mb(), 2048); // Clamped to maximum
    }

    #[test]
    fn test_clamp_block_cache() {
        let tuning = DbTuning {
            block_cache_mb: Some(32), // Too low
            ..Default::default()
        };
        let clamped = tuning.validate_and_clamp();
        assert_eq!(clamped.block_cache_mb(), 64); // Clamped to minimum

        let tuning2 = DbTuning {
            block_cache_mb: Some(20000), // Too high
            ..Default::default()
        };
        let clamped2 = tuning2.validate_and_clamp();
        assert_eq!(clamped2.block_cache_mb(), 16384); // Clamped to maximum
    }

    #[test]
    fn test_invalid_compression() {
        let tuning = DbTuning {
            compression: Some("bzip2".into()), // Invalid
            ..Default::default()
        };
        let clamped = tuning.validate_and_clamp();
        assert_eq!(clamped.compression(), "zstd"); // Reset to default
    }

    #[test]
    fn test_clamp_background_jobs() {
        let tuning = DbTuning {
            max_background_jobs: Some(0), // Too low
            ..Default::default()
        };
        let clamped = tuning.validate_and_clamp();
        assert_eq!(clamped.max_background_jobs(), 1); // Clamped to minimum

        let tuning2 = DbTuning {
            max_background_jobs: Some(32), // Too high
            ..Default::default()
        };
        let clamped2 = tuning2.validate_and_clamp();
        assert_eq!(clamped2.max_background_jobs(), 16); // Clamped to maximum
    }

    #[test]
    fn test_valid_values_not_clamped() {
        let tuning = DbTuning {
            write_buffer_mb: Some(512),      // Valid
            block_cache_mb: Some(1024),      // Valid
            compression: Some("lz4".into()), // Valid
            ..Default::default()
        };
        let clamped = tuning.validate_and_clamp();
        assert_eq!(clamped.write_buffer_mb(), 512);
        assert_eq!(clamped.block_cache_mb(), 1024);
        assert_eq!(clamped.compression(), "lz4");
    }
}
