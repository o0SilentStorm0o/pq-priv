use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, warn};

use crate::codec::{read_message, write_message};
use crate::config::P2pConfig;
use crate::error::NetworkError;
use crate::handshake::{PeerRole, perform_handshake};
use crate::router::Router;
use crate::types::{NetMessage, PeerId, Version};

const MESSAGE_INTERVAL: Duration = Duration::from_secs(60);
const MESSAGE_LIMIT: usize = 2048;
const PING_INTERVAL: Duration = Duration::from_secs(30);

pub async fn spawn_peer(
    mut stream: TcpStream,
    role: PeerRole,
    router: Router,
    config: P2pConfig,
    local_version: Version,
    remote_addr: SocketAddr,
) -> Result<(), NetworkError> {
    let remote_version =
        perform_handshake(&mut stream, role, &local_version, config.max_message_size)
            .await
            .map_err(NetworkError::from)?;

    let (reader, writer) = stream.into_split();
    let (tx, rx) = mpsc::channel(config.outbound_queue);
    let peer_id = router.register_peer(
        matches!(role, PeerRole::Inbound),
        remote_addr.to_string(),
        remote_version,
        tx.clone(),
    )?;

    tokio::spawn(read_loop(
        peer_id,
        router.clone(),
        reader,
        config.max_message_size,
    ));

    tokio::spawn(write_loop(peer_id, router.clone(), writer, rx));

    tokio::spawn(ping_loop(peer_id, tx));

    Ok(())
}

async fn read_loop(
    peer_id: PeerId,
    router: Router,
    mut reader: tokio::net::tcp::OwnedReadHalf,
    max_size: usize,
) {
    let mut counter = 0usize;
    let mut window = Instant::now();
    loop {
        match read_message(&mut reader, max_size).await {
            Ok(message) => {
                counter += 1;
                if window.elapsed() >= MESSAGE_INTERVAL {
                    window = Instant::now();
                    counter = 0;
                }
                if counter > MESSAGE_LIMIT {
                    warn!(%peer_id, "peer exceeded message rate limit");
                    router.disconnect(peer_id, "rate limit exceeded");
                    break;
                }
                router.emit_message(peer_id, message);
            }
            Err(err) => {
                debug!(%peer_id, error = ?err, "peer read loop exiting");
                router.disconnect(peer_id, err.to_string());
                break;
            }
        }
    }
}

async fn write_loop(
    peer_id: PeerId,
    router: Router,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<NetMessage>,
) {
    while let Some(message) = rx.recv().await {
        if let Err(err) = write_message(&mut writer, &message).await {
            warn!(%peer_id, error = ?err, "failed to send message");
            router.disconnect(peer_id, err.to_string());
            break;
        }
    }
}

async fn ping_loop(_peer_id: PeerId, tx: mpsc::Sender<NetMessage>) {
    let mut ticker = interval(PING_INTERVAL);
    loop {
        ticker.tick().await;
        if tx.send(NetMessage::Ping(rand::random())).await.is_err() {
            break;
        }
    }
}
