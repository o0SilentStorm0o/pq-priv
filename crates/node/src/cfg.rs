use std::net::SocketAddr;

/// High level runtime configuration for the reference node.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub p2p_listen: SocketAddr,
    pub rpc_listen: SocketAddr,
    pub seeds: Vec<SocketAddr>,
    pub max_mempool_bytes: usize,
    pub max_orphans: usize,
    pub blocks: u32,
}

impl NodeConfig {
    pub fn new(
        p2p_listen: SocketAddr,
        rpc_listen: SocketAddr,
        seeds: Vec<SocketAddr>,
        max_mempool_bytes: usize,
        max_orphans: usize,
        blocks: u32,
    ) -> Self {
        Self {
            p2p_listen,
            rpc_listen,
            seeds,
            max_mempool_bytes,
            max_orphans,
            blocks,
        }
    }
}
