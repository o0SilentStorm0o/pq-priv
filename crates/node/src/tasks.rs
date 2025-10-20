use std::sync::Arc;

use parking_lot::Mutex;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::relay::Relay;
use crate::state::{ChainEvent, ChainState};
use crate::sync::SyncManager;
use p2p::{NetMessage, NetworkHandle, PeerEvent};

pub async fn run_peer_event_loop(relay: Relay) {
    let network = relay.network();
    let mut events = network.subscribe();
    loop {
        match events.recv().await {
            Ok(PeerEvent::Message { peer_id, message }) => match message {
                NetMessage::Inv(inventory) => relay.handle_inv(peer_id, inventory),
                NetMessage::GetData(inventory) => relay.handle_get_data(peer_id, inventory),
                NetMessage::GetHeaders { locator, stop_hash } => {
                    relay.handle_get_headers(peer_id, locator, stop_hash);
                }
                NetMessage::Headers(headers) => relay.handle_headers(peer_id, headers),
                NetMessage::Tx(bytes) => relay.handle_tx(peer_id, bytes),
                NetMessage::Block(bytes) => relay.handle_block(peer_id, bytes),
                NetMessage::Ping(nonce) => {
                    let _ = network.send(peer_id, NetMessage::Pong(nonce));
                }
                NetMessage::Version(_) | NetMessage::VerAck | NetMessage::Pong(_) => {}
                NetMessage::GetAddr | NetMessage::Addr(_) | NetMessage::Reject { .. } => {}
            },
            Ok(PeerEvent::Connected(summary)) => {
                info!(peer = %summary.peer_id, height = summary.best_height, "peer connected");
            }
            Ok(PeerEvent::Disconnected { peer_id, reason }) => {
                info!(%peer_id, %reason, "peer disconnected");
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "peer event loop lagged");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

pub async fn run_block_sync_task(chain: Arc<Mutex<ChainState>>, network: NetworkHandle) {
    request_headers(&chain, &network);
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        request_headers(&chain, &network);
    }
}

fn request_headers(chain: &Arc<Mutex<ChainState>>, network: &NetworkHandle) {
    let locator = {
        let guard = chain.lock();
        guard.block_locator()
    };
    if locator.is_empty() {
        return;
    }
    let tip_height = {
        let guard = chain.lock();
        guard.height()
    };
    debug!(
        len = locator.len(),
        tip_height, "broadcasting GetHeaders for block sync"
    );
    network.broadcast(NetMessage::GetHeaders {
        locator,
        stop_hash: None,
    });
}

pub async fn run_chain_event_loop(
    chain: Arc<Mutex<ChainState>>,
    sync: Arc<SyncManager>,
    network: NetworkHandle,
) {
    let mut receiver = {
        let guard = chain.lock();
        guard.subscribe()
    };

    {
        let guard = chain.lock();
        let header = guard.tip().header.clone();
        let height = guard.height();
        sync.register_headers(std::slice::from_ref(&header), &guard);
        network.update_best_height(height);
    }

    loop {
        match receiver.recv().await {
            Ok(ChainEvent::TipUpdated { height, header, .. }) => {
                {
                    let guard = chain.lock();
                    sync.register_headers(std::slice::from_ref(&header), &guard);
                }
                network.update_best_height(height);
                debug!(height, "registered new tip headers");
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "chain event loop lagged");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}
