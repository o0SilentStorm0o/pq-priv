use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc};

use crate::error::NetworkError;
use crate::types::{NetMessage, PeerId, Services, Version};

const EVENT_CHANNEL_SIZE: usize = 2048; // Increased from 128 to handle large sync bursts

#[derive(Clone, Debug)]
pub struct PeerSummary {
    pub peer_id: PeerId,
    pub inbound: bool,
    pub address: String,
    pub user_agent: String,
    pub best_height: u64,
    pub services: Services,
    pub connected_at: Instant,
}

#[derive(Clone, Debug)]
pub enum PeerEvent {
    Connected(PeerSummary),
    Disconnected {
        peer_id: PeerId,
        reason: String,
    },
    Message {
        peer_id: PeerId,
        message: NetMessage,
    },
}

#[derive(Clone)]
pub struct Router {
    inner: Arc<RouterInner>,
}

struct RouterInner {
    peers: RwLock<HashMap<PeerId, PeerHandle>>,
    events: broadcast::Sender<PeerEvent>,
    max_peers: usize,
}

struct PeerHandle {
    sender: mpsc::Sender<NetMessage>,
    summary: PeerSummary,
}

impl Router {
    pub fn new(max_peers: usize) -> Self {
        let (events, _) = broadcast::channel(EVENT_CHANNEL_SIZE);
        Self {
            inner: Arc::new(RouterInner {
                peers: RwLock::new(HashMap::new()),
                events,
                max_peers,
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.inner.events.subscribe()
    }

    pub fn register_peer(
        &self,
        inbound: bool,
        address: String,
        version: Version,
        sender: mpsc::Sender<NetMessage>,
    ) -> Result<PeerId, NetworkError> {
        let mut peers = self.inner.peers.write();
        if peers.len() >= self.inner.max_peers {
            return Err(NetworkError::Capacity);
        }
        let peer_id = PeerId::random();
        let summary = PeerSummary {
            peer_id,
            inbound,
            address,
            user_agent: version.user_agent.clone(),
            best_height: version.best_height,
            services: version.services,
            connected_at: Instant::now(),
        };
        peers.insert(
            peer_id,
            PeerHandle {
                sender,
                summary: summary.clone(),
            },
        );
        let _ = self.inner.events.send(PeerEvent::Connected(summary));
        Ok(peer_id)
    }

    pub fn disconnect(&self, peer_id: PeerId, reason: impl Into<String>) {
        let mut peers = self.inner.peers.write();
        if peers.remove(&peer_id).is_some() {
            let _ = self.inner.events.send(PeerEvent::Disconnected {
                peer_id,
                reason: reason.into(),
            });
        }
    }

    pub fn send(&self, peer_id: PeerId, message: NetMessage) -> Result<(), NetworkError> {
        let peers = self.inner.peers.read();
        let handle = peers
            .get(&peer_id)
            .ok_or(NetworkError::UnknownPeer(peer_id))?;
        let sender = handle.sender.clone();
        drop(peers);
        tokio::spawn(async move {
            let _ = sender.send(message).await;
        });
        Ok(())
    }

    pub fn broadcast(&self, message: NetMessage, except: Option<PeerId>) {
        let peers = self.inner.peers.read();
        for (&peer_id, handle) in peers.iter() {
            if Some(peer_id) == except {
                continue;
            }
            let sender = handle.sender.clone();
            let msg = message.clone();
            tokio::spawn(async move {
                let _ = sender.send(msg).await;
            });
        }
    }

    pub fn peer_summaries(&self) -> Vec<PeerSummary> {
        self.inner
            .peers
            .read()
            .values()
            .map(|handle| handle.summary.clone())
            .collect()
    }

    pub fn emit_message(&self, peer_id: PeerId, message: NetMessage) {
        let _ = self
            .inner
            .events
            .send(PeerEvent::Message { peer_id, message });
    }
}
