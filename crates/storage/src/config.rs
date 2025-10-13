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
    pub fn from_env(mut self) -> Self {
        use std::env;

        if let Ok(val) = env::var("PQPRIV_DB_MAX_BACKGROUND_JOBS") {
            if let Ok(num) = val.parse() {
                self.max_background_jobs = Some(num);
            }
        }
        if let Ok(val) = env::var("PQPRIV_DB_WRITE_BUFFER_MB") {
            if let Ok(num) = val.parse() {
                self.write_buffer_mb = Some(num);
            }
        }
        if let Ok(val) = env::var("PQPRIV_DB_TARGET_FILE_SIZE_MB") {
            if let Ok(num) = val.parse() {
                self.target_file_size_mb = Some(num);
            }
        }
        if let Ok(val) = env::var("PQPRIV_DB_COMPRESSION") {
            self.compression = Some(val);
        }
        if let Ok(val) = env::var("PQPRIV_DB_BLOCK_CACHE_MB") {
            if let Ok(num) = val.parse() {
                self.block_cache_mb = Some(num);
            }
        }
        if let Ok(val) = env::var("PQPRIV_DB_WAL_ENABLED") {
            self.wal_enabled = Some(val == "true" || val == "1" || val == "on");
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
}
