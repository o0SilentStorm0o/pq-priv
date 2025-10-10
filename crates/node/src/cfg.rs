use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::mempool::TxPoolConfig;

/// High level runtime configuration for the reference node.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub p2p_listen: SocketAddr,
    pub rpc_listen: SocketAddr,
    pub seeds: Vec<SocketAddr>,
    pub db_path: PathBuf,
    pub snapshots_path: PathBuf,
    pub snapshot_interval: u64,
    pub snapshot_keep: usize,
    pub mempool: TxPoolConfig,
    pub sync_orphan_limit: usize,
    pub sync_orphan_ttl: Duration,
}

impl NodeConfig {
    pub fn with_defaults() -> Self {
        Self::default()
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            p2p_listen: "0.0.0.0:9333".parse().expect("valid listen address"),
            rpc_listen: "127.0.0.1:8645".parse().expect("valid rpc address"),
            seeds: Vec::new(),
            db_path: PathBuf::from(".pqpriv/node"),
            snapshots_path: PathBuf::from(".pqpriv/snapshots"),
            snapshot_interval: 1_000,
            snapshot_keep: 3,
            mempool: TxPoolConfig::default(),
            sync_orphan_limit: 4_096,
            sync_orphan_ttl: Duration::from_secs(120),
        }
    }
}
