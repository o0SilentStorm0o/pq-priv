use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::config::P2pConfig;
use crate::error::NetworkError;
use crate::handshake::PeerRole;
use crate::peer::spawn_peer;
use crate::router::{PeerEvent, PeerSummary, Router};
use crate::types::{NetMessage, PeerId, Version};

#[derive(Clone)]
pub struct NetworkHandle {
    router: Router,
    config: P2pConfig,
    version: Arc<RwLock<Version>>,
}

impl NetworkHandle {
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<PeerEvent> {
        self.router.subscribe()
    }

    pub fn broadcast(&self, message: NetMessage) {
        self.router.broadcast(message, None);
    }

    pub fn broadcast_except(&self, message: NetMessage, except: Option<PeerId>) {
        self.router.broadcast(message, except);
    }

    pub fn send(&self, peer_id: PeerId, message: NetMessage) -> Result<(), NetworkError> {
        self.router.send(peer_id, message)
    }

    pub fn peer_info(&self) -> Vec<PeerSummary> {
        self.router.peer_summaries()
    }

    pub fn update_best_height(&self, height: u64) {
        self.version.write().best_height = height;
    }

    pub fn local_version(&self) -> Version {
        self.version.read().clone()
    }

    pub fn config(&self) -> &P2pConfig {
        &self.config
    }
}

pub async fn start_network(
    config: P2pConfig,
    local_version: Version,
) -> Result<NetworkHandle, NetworkError> {
    let router = Router::new(config.max_peers);
    let version = Arc::new(RwLock::new(local_version));
    let listener = TcpListener::bind(config.listen).await?;
    info!(addr = %config.listen, "p2p listening");

    let listener_router = router.clone();
    let listener_config = config.clone();
    let listener_version = version.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let router = listener_router.clone();
                    let config = listener_config.clone();
                    let version_snapshot = listener_version.read().clone();
                    tokio::spawn(async move {
                        if let Err(err) = spawn_peer(
                            stream,
                            PeerRole::Inbound,
                            router,
                            config,
                            version_snapshot,
                            addr,
                        )
                        .await
                        {
                            warn!(remote = %addr, error = ?err, "failed to accept peer");
                        }
                    });
                }
                Err(err) => {
                    warn!(error = ?err, "listener accept failed");
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });

    for seed in &config.seeds {
        let router = router.clone();
        let config = config.clone();
        let version_snapshot = version.clone();
        let seed_addr = *seed;
        tokio::spawn(async move {
            loop {
                match tokio::net::TcpStream::connect(seed_addr).await {
                    Ok(stream) => {
                        let version = version_snapshot.read().clone();
                        match spawn_peer(
                            stream,
                            PeerRole::Outbound,
                            router.clone(),
                            config.clone(),
                            version,
                            seed_addr,
                        )
                        .await
                        {
                            Ok(()) => {
                                debug!(target = %seed_addr, "outbound peer connected");
                                break;
                            }
                            Err(err) => {
                                warn!(target = %seed_addr, error = ?err, "outbound handshake failed");
                            }
                        }
                    }
                    Err(err) => {
                        warn!(target = %seed_addr, error = ?err, "outbound connect failed");
                    }
                }
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    Ok(NetworkHandle {
        router,
        config,
        version,
    })
}
