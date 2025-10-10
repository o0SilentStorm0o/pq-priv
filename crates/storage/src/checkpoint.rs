use std::fs;
use std::path::PathBuf;

use crate::errors::StorageError;
use crate::store::Store;

#[derive(Clone, Debug)]
pub struct SnapshotConfig {
    pub directory: PathBuf,
    pub interval: u64,
    pub keep: usize,
}

impl SnapshotConfig {
    pub fn new(directory: PathBuf, interval: u64, keep: usize) -> Self {
        Self {
            directory,
            interval,
            keep,
        }
    }

    pub fn should_snapshot(&self, height: u64) -> bool {
        self.interval > 0 && height % self.interval == 0
    }
}

pub struct CheckpointManager {
    store: Store,
}

impl CheckpointManager {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub fn maybe_snapshot(
        &self,
        config: &SnapshotConfig,
        height: u64,
    ) -> Result<Option<PathBuf>, StorageError> {
        if !config.should_snapshot(height) {
            return Ok(None);
        }
        fs::create_dir_all(&config.directory)?;
        let path = config.directory.join(format!("snapshot-{height}"));
        self.store.create_checkpoint(&path)?;
        self.prune_old(config)?;
        Ok(Some(path))
    }

    fn prune_old(&self, config: &SnapshotConfig) -> Result<(), StorageError> {
        if config.keep == 0 {
            return Ok(());
        }
        let mut snapshots: Vec<PathBuf> = fs::read_dir(&config.directory)?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.is_dir())
            .collect();
        snapshots.sort_by(|a, b| a.cmp(b));
        while snapshots.len() > config.keep {
            let path = snapshots.remove(0);
            fs::remove_dir_all(&path)?;
        }
        Ok(())
    }
}
