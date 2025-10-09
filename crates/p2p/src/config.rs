use std::net::SocketAddr;

use blake3::hash;

/// Runtime configuration for the peer-to-peer stack.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// Address on which to accept inbound peers.
    pub listen: SocketAddr,
    /// Known peers to dial on startup.
    pub seeds: Vec<SocketAddr>,
    /// Maximum number of fully connected peers.
    pub max_peers: usize,
    /// Maximum messages queued per peer before disconnecting.
    pub outbound_queue: usize,
    /// Maximum bytes per message frame.
    pub max_message_size: usize,
    /// Shared secret used to authenticate version handshakes.
    pub handshake_key: [u8; 32],
}

impl Default for P2pConfig {
    fn default() -> Self {
        let handshake_key = hash(b"pq-priv-handshake-v1").into();
        Self {
            listen: "127.0.0.1:8644".parse().expect("loopback"),
            seeds: Vec::new(),
            max_peers: 32,
            outbound_queue: 64,
            max_message_size: 2 * 1024 * 1024,
            handshake_key,
        }
    }
}
