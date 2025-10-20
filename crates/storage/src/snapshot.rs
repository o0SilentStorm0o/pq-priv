//! Snapshot and restore functionality for RocksDB storage.
//!
//! # Security considerations
//! - All paths are canonicalized to prevent path traversal attacks
//! - Symlinks are explicitly rejected during restore
//! - Atomic operations (temp directory + rename) ensure no partial snapshots
//! - Metadata validation ensures chain compatibility

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use tar::{Archive, Builder};
use tracing::{debug, info, warn};

use crate::{StorageError, Store, TipInfo};

/// Snapshot metadata containing chain state at snapshot time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Block height at snapshot time
    pub height: u64,
    /// Tip block hash
    pub tip_hash: String,
    /// Cumulative chain work (hex encoded)
    pub cumulative_work: String,
    /// Total UTXO count in the set
    pub utxo_count: u64,
    /// Unix timestamp when snapshot was created
    pub timestamp: u64,
    /// RocksDB column families included
    pub column_families: Vec<String>,
    /// Format version for compatibility checking
    pub format_version: u32,
}

impl SnapshotMetadata {
    /// Create metadata from current store state.
    pub fn from_tip_info(tip: &TipInfo, utxo_count: u64, column_families: Vec<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        Self {
            height: tip.height,
            tip_hash: hex::encode(tip.hash),
            cumulative_work: tip.cumulative_work.to_str_radix(16),
            utxo_count,
            timestamp,
            column_families,
            format_version: 1,
        }
    }

    /// Parse cumulative work from hex string.
    pub fn parse_cumulative_work(&self) -> Result<BigUint, StorageError> {
        BigUint::from_str_radix(&self.cumulative_work, 16).map_err(|_| {
            StorageError::Corrupted(
                format!(
                    "invalid cumulative work in metadata: {}",
                    self.cumulative_work
                )
                .into(),
            )
        })
    }

    /// Parse tip hash from hex string.
    pub fn parse_tip_hash(&self) -> Result<[u8; 32], StorageError> {
        let bytes = hex::decode(&self.tip_hash).map_err(|e| {
            StorageError::Corrupted(format!("invalid tip hash in metadata: {}", e).into())
        })?;

        if bytes.len() != 32 {
            return Err(StorageError::Corrupted(
                format!("tip hash must be 32 bytes, got {}", bytes.len()).into(),
            ));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }
}

/// Snapshot creation and restoration manager.
pub struct SnapshotManager {
    /// Directory where snapshots are stored
    snapshot_dir: PathBuf,
}

impl SnapshotManager {
    /// Create a new snapshot manager.
    pub fn new(snapshot_dir: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let snapshot_dir = snapshot_dir.into();
        fs::create_dir_all(&snapshot_dir)?;
        Ok(Self { snapshot_dir })
    }

    /// Create a snapshot of the current database state.
    ///
    /// # Security
    /// - Uses RocksDB checkpoint for consistency
    /// - Atomic write via temporary directory + rename
    /// - Validates all paths before operations
    pub fn create_snapshot(&self, store: &Store, utxo_count: u64) -> Result<PathBuf, StorageError> {
        let tip = store.tip()?.ok_or(StorageError::MissingMeta("tip"))?;

        info!(
            height = tip.height,
            hash = hex::encode(tip.hash),
            "creating database snapshot"
        );

        // Create temporary checkpoint directory
        let temp_dir =
            self.snapshot_dir
                .join(format!("temp-{}-{}", tip.height, std::process::id()));
        if temp_dir.exists() {
            fs::remove_dir_all(&temp_dir).map_err(|e| {
                StorageError::Corrupted(format!("failed to remove old temp dir: {}", e).into())
            })?;
        }

        fs::create_dir_all(&temp_dir)?;

        // Create RocksDB checkpoint (RocksDB will create checkpoint_dir itself)
        let checkpoint_dir = temp_dir.join("checkpoint");
        store.create_checkpoint(&checkpoint_dir)?;

        // Create metadata
        let column_families = vec![
            "default".to_string(),
            "headers".to_string(),
            "blocks".to_string(),
            "utxos".to_string(),
        ];

        let metadata = SnapshotMetadata::from_tip_info(&tip, utxo_count, column_families);
        let metadata_path = temp_dir.join("metadata.json");
        let metadata_json = serde_json::to_string_pretty(&metadata)?;

        fs::write(&metadata_path, metadata_json)?;

        // Create tar.gz archive
        let snapshot_name = format!("snap-{:010}-{}.tar.gz", tip.height, metadata.timestamp);
        let snapshot_path = self.snapshot_dir.join(&snapshot_name);
        let temp_archive = self.snapshot_dir.join(format!("{}.tmp", snapshot_name));

        debug!(path = %temp_archive.display(), "creating snapshot archive");
        self.create_archive(&temp_dir, &temp_archive)?;

        // Atomic rename
        fs::rename(&temp_archive, &snapshot_path)?;

        // Cleanup temporary directory (non-fatal on error)
        if let Err(e) = fs::remove_dir_all(&temp_dir) {
            warn!("failed to cleanup temp directory: {}", e);
        }

        info!(
            path = %snapshot_path.display(),
            size_mb = snapshot_path.metadata().ok().map(|m| m.len() / 1024 / 1024),
            "snapshot created successfully"
        );

        Ok(snapshot_path)
    }

    /// Restore database from a snapshot archive.
    ///
    /// # Security
    /// - Validates metadata compatibility
    /// - Rejects symlinks and path traversal attempts
    /// - Extracts to temporary directory first
    /// - Atomic move to target directory
    pub fn restore_snapshot(
        &self,
        snapshot_path: &Path,
        target_dir: &Path,
    ) -> Result<SnapshotMetadata, StorageError> {
        info!(
            snapshot = %snapshot_path.display(),
            target = %target_dir.display(),
            "restoring database from snapshot"
        );

        // Validate snapshot path
        let snapshot_path = self.validate_path(snapshot_path)?;

        // Create temporary extraction directory
        let temp_dir = target_dir
            .parent()
            .ok_or(StorageError::MissingMeta("target directory parent"))?;
        let extract_dir = temp_dir.join(format!("restore-temp-{}", std::process::id()));

        if extract_dir.exists() {
            fs::remove_dir_all(&extract_dir)?;
        }

        fs::create_dir_all(&extract_dir)?;

        // Extract archive with security checks
        debug!(path = %extract_dir.display(), "extracting snapshot");
        self.extract_archive_secure(&snapshot_path, &extract_dir)?;

        // Load and validate metadata
        let metadata_path = extract_dir.join("metadata.json");
        let metadata = self.load_metadata(&metadata_path)?;

        info!(
            height = metadata.height,
            tip_hash = %metadata.tip_hash,
            utxo_count = metadata.utxo_count,
            "snapshot metadata validated"
        );

        // Verify checkpoint directory exists
        let checkpoint_dir = extract_dir.join("checkpoint");
        if !checkpoint_dir.exists() {
            return Err(StorageError::Corrupted(
                "snapshot missing checkpoint directory".into(),
            ));
        }

        // Atomic move to target directory
        if target_dir.exists() {
            warn!(path = %target_dir.display(), "target directory exists, removing");
            fs::remove_dir_all(target_dir)?;
        }

        fs::rename(&checkpoint_dir, target_dir)?;

        // Cleanup extraction directory (non-fatal on error)
        if let Err(e) = fs::remove_dir_all(&extract_dir) {
            warn!("failed to cleanup extract directory: {}", e);
        }

        info!(
            path = %target_dir.display(),
            "database restored successfully"
        );

        Ok(metadata)
    }

    /// Load and validate metadata from a JSON file.
    fn load_metadata(&self, path: &Path) -> Result<SnapshotMetadata, StorageError> {
        let file = File::open(path)?;
        let metadata: SnapshotMetadata = serde_json::from_reader(BufReader::new(file))?;

        // Validate format version
        if metadata.format_version != 1 {
            return Err(StorageError::Corrupted(
                format!(
                    "unsupported snapshot format version: {}",
                    metadata.format_version
                )
                .into(),
            ));
        }

        // Validate tip hash can be decoded
        metadata.parse_tip_hash()?;

        // Validate cumulative work can be parsed
        metadata.parse_cumulative_work()?;

        Ok(metadata)
    }

    /// Create a tar.gz archive from a directory.
    fn create_archive(&self, source_dir: &Path, archive_path: &Path) -> Result<(), StorageError> {
        let file = File::create(archive_path)?;
        let encoder = GzEncoder::new(BufWriter::new(file), Compression::default());
        let mut tar = Builder::new(encoder);

        // Add metadata.json
        let metadata_path = source_dir.join("metadata.json");
        tar.append_path_with_name(&metadata_path, "metadata.json")?;

        // Add checkpoint directory
        let checkpoint_dir = source_dir.join("checkpoint");
        tar.append_dir_all("checkpoint", &checkpoint_dir)?;

        // Finish tar builder and get encoder
        let encoder = tar.into_inner()?;

        // Finish gzip encoder to flush all data
        encoder.finish()?;

        Ok(())
    }

    /// Extract archive with security checks (reject symlinks, path traversal).
    fn extract_archive_secure(
        &self,
        archive_path: &Path,
        target_dir: &Path,
    ) -> Result<(), StorageError> {
        let file = File::open(archive_path)?;
        let decoder = GzDecoder::new(BufReader::new(file));
        let mut archive = Archive::new(decoder);

        // Canonicalize target directory for path validation
        let canonical_target = target_dir.canonicalize()?;

        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;

            // Security: Reject absolute paths
            if path.is_absolute() {
                return Err(StorageError::Corrupted(
                    format!("snapshot contains absolute path: {}", path.display()).into(),
                ));
            }

            // Security: Reject path traversal
            if path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(StorageError::Corrupted(
                    format!("snapshot contains path traversal: {}", path.display()).into(),
                ));
            }

            let target_path = target_dir.join(&*path);

            // Security: Ensure target is within extraction directory
            let canonical_entry = match target_path.canonicalize() {
                Ok(p) => p,
                Err(_) => {
                    // Path doesn't exist yet, check parent
                    let parent = target_path
                        .parent()
                        .ok_or(StorageError::MissingMeta("entry path parent"))?;
                    let canonical_parent = parent.canonicalize()?;
                    canonical_parent.join(target_path.file_name().unwrap())
                }
            };

            if !canonical_entry.starts_with(&canonical_target) {
                return Err(StorageError::Corrupted(
                    format!(
                        "snapshot entry escapes target directory: {}",
                        path.display()
                    )
                    .into(),
                ));
            }

            // Security: Reject symlinks
            let header = entry.header();
            if header.entry_type().is_symlink() || header.entry_type().is_hard_link() {
                return Err(StorageError::Corrupted(
                    format!("snapshot contains symlink: {}", path.display()).into(),
                ));
            }

            // Extract entry
            entry.unpack(&target_path)?;
        }

        Ok(())
    }

    /// Validate and canonicalize a file path.
    fn validate_path(&self, path: &Path) -> Result<PathBuf, StorageError> {
        if !path.exists() {
            return Err(StorageError::Corrupted(
                format!("path does not exist: {}", path.display()).into(),
            ));
        }

        path.canonicalize().map_err(|e| e.into())
    }

    /// List available snapshots in the snapshot directory.
    pub fn list_snapshots(&self) -> Result<Vec<PathBuf>, StorageError> {
        let mut snapshots = Vec::new();

        for entry in fs::read_dir(&self.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("gz")
                && path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with("snap-"))
            {
                snapshots.push(path);
            }
        }

        // Sort by filename (height is zero-padded)
        snapshots.sort();

        Ok(snapshots)
    }

    /// Cleanup old snapshots, keeping only the N most recent.
    pub fn cleanup_old_snapshots(&self, keep: usize) -> Result<usize, StorageError> {
        let mut snapshots = self.list_snapshots()?;

        if snapshots.len() <= keep {
            return Ok(0);
        }

        // Sort by modification time (oldest first)
        snapshots.sort_by_key(|p| {
            p.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

        let to_remove = snapshots.len() - keep;
        let mut removed = 0;

        for snapshot in snapshots.iter().take(to_remove) {
            match fs::remove_file(snapshot) {
                Ok(_) => {
                    info!(path = %snapshot.display(), "removed old snapshot");
                    removed += 1;
                }
                Err(e) => {
                    warn!(path = %snapshot.display(), error = %e, "failed to remove snapshot");
                }
            }
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_roundtrip() {
        let tip = TipInfo::new(1000, [42u8; 32], BigUint::from(12345u64), 5);

        let metadata = SnapshotMetadata::from_tip_info(&tip, 5000, vec!["default".to_string()]);

        assert_eq!(metadata.height, 1000);
        assert_eq!(metadata.utxo_count, 5000);
        assert_eq!(metadata.parse_tip_hash().unwrap(), [42u8; 32]);
        assert_eq!(
            metadata.parse_cumulative_work().unwrap(),
            BigUint::from(12345u64)
        );
    }

    #[test]
    fn test_invalid_metadata() {
        let mut metadata = SnapshotMetadata {
            height: 100,
            tip_hash: "invalid-hex".to_string(),
            cumulative_work: "3039".to_string(),
            utxo_count: 1000,
            timestamp: 1234567890,
            column_families: vec![],
            format_version: 1,
        };

        assert!(metadata.parse_tip_hash().is_err());

        metadata.tip_hash = hex::encode([1u8; 32]);
        metadata.cumulative_work = "not-hex".to_string();

        assert!(metadata.parse_cumulative_work().is_err());
    }
}
