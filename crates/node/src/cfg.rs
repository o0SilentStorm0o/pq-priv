use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use storage::DbTuning;
use tracing::info;

use crate::mempool::TxPoolConfig;

/// High level runtime configuration for the reference node.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub p2p_listen: SocketAddr,
    pub rpc_listen: SocketAddr,
    pub seeds: Vec<SocketAddr>,
    pub db_path: PathBuf,
    pub db_tuning: DbTuning,
    pub snapshots_path: PathBuf,
    pub snapshot_interval: u64,
    pub snapshot_keep: usize,
    pub mempool: TxPoolConfig,
    pub sync_orphan_limit: usize,
    pub sync_orphan_ttl: Duration,
}

impl NodeConfig {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut config = Self::default();
        let candidate = path.map(PathBuf::from).unwrap_or_else(default_config_path);
        if !candidate.exists() {
            if let Some(explicit) = path {
                info!(path = %explicit.display(), "configuration file not found, using defaults");
            }
            // Apply environment variable overrides to DbTuning
            config.db_tuning = DbTuning::from_env(config.db_tuning);
            return Ok(config);
        }

        let contents = fs::read_to_string(&candidate)
            .with_context(|| format!("failed to read config at {}", candidate.display()))?;
        let raw: RawNodeConfig = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config at {}", candidate.display()))?;

        if let Some(listen) = raw.p2p_listen {
            config.p2p_listen = listen;
        }
        if let Some(listen) = raw.rpc_listen {
            config.rpc_listen = listen;
        }
        if let Some(seeds) = raw.seeds {
            config.seeds = seeds;
        }
        if let Some(path) = raw.db_path {
            config.db_path = path;
        }
        if let Some(db) = raw.db {
            // Apply TOML config
            if let Some(write_buffer_mb) = db.write_buffer_mb {
                config.db_tuning.write_buffer_mb = write_buffer_mb;
            }
            if let Some(block_cache_mb) = db.block_cache_mb {
                config.db_tuning.block_cache_mb = block_cache_mb;
            }
            if let Some(compression) = db.compression {
                config.db_tuning.compression = compression;
            }
        }
        // Apply environment variable overrides (highest priority)
        config.db_tuning = DbTuning::from_env(config.db_tuning);
        
        if let Some(path) = raw.snapshots_path {
            config.snapshots_path = path;
        }
        if let Some(interval) = raw.snapshot_interval {
            config.snapshot_interval = interval;
        }
        if let Some(keep) = raw.snapshot_keep {
            config.snapshot_keep = keep;
        }
        if let Some(limit) = raw.sync_orphan_limit {
            config.sync_orphan_limit = limit;
        }
        if let Some(ttl) = raw.sync_orphan_ttl_secs {
            config.sync_orphan_ttl = Duration::from_secs(ttl);
        }
        if let Some(mempool) = raw.mempool {
            if let Some(max_bytes) = mempool.max_bytes {
                config.mempool.max_bytes = max_bytes;
            }
            if let Some(max_orphans) = mempool.max_orphans {
                config.mempool.max_orphans = max_orphans;
            }
            if let Some(min_fee) = mempool.min_relay_fee_sat_vb {
                config.mempool.min_relay_fee_sat_vb = min_fee;
            }
            if let Some(ttl) = mempool.orphan_ttl_secs {
                config.mempool.orphan_ttl = Duration::from_secs(ttl);
            }
        }

        info!(path = %candidate.display(), "loaded configuration overrides");
        Ok(config)
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            p2p_listen: "0.0.0.0:9333".parse().expect("valid listen address"),
            rpc_listen: "127.0.0.1:8645".parse().expect("valid rpc address"),
            seeds: Vec::new(),
            db_path: PathBuf::from(".pqpriv/node"),
            db_tuning: DbTuning::default(),
            snapshots_path: PathBuf::from(".pqpriv/snapshots"),
            snapshot_interval: 1_000,
            snapshot_keep: 3,
            mempool: TxPoolConfig::default(),
            sync_orphan_limit: 4_096,
            sync_orphan_ttl: Duration::from_secs(120),
        }
    }
}

fn default_config_path() -> PathBuf {
    PathBuf::from("node.toml")
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct RawNodeConfig {
    p2p_listen: Option<SocketAddr>,
    rpc_listen: Option<SocketAddr>,
    seeds: Option<Vec<SocketAddr>>,
    db_path: Option<PathBuf>,
    db: Option<RawDbConfig>,
    snapshots_path: Option<PathBuf>,
    snapshot_interval: Option<u64>,
    snapshot_keep: Option<usize>,
    mempool: Option<RawTxPoolConfig>,
    sync_orphan_limit: Option<usize>,
    sync_orphan_ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct RawDbConfig {
    write_buffer_mb: Option<usize>,
    block_cache_mb: Option<usize>,
    compression: Option<String>,
}

#[derive(Debug, Deserialize, Default)]]
#[serde(default)]
struct RawTxPoolConfig {
    max_bytes: Option<usize>,
    max_orphans: Option<usize>,
    min_relay_fee_sat_vb: Option<u64>,
    orphan_ttl_secs: Option<u64>,
}
