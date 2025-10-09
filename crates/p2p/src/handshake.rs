use std::io;
use std::time::Duration;

use blake3::Hasher;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::codec::{read_message, write_message};
use crate::error::{HandshakeError, NetworkError};
use crate::types::{NetMessage, NodeAddr, Version};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    Inbound,
    Outbound,
}

pub async fn perform_handshake<S>(
    stream: &mut S,
    role: PeerRole,
    local_version: &Version,
    max_len: usize,
    handshake_key: &[u8; 32],
) -> Result<Version, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match role {
        PeerRole::Outbound => {
            let signed = attach_auth(local_version.clone(), handshake_key);
            write_message(stream, &NetMessage::Version(signed))
                .await
                .map_err(map_network_error)?;
            let remote = expect_version(stream, max_len, handshake_key).await?;
            write_message(stream, &NetMessage::VerAck)
                .await
                .map_err(map_network_error)?;
            expect_verack(stream, max_len).await?;
            Ok(remote)
        }
        PeerRole::Inbound => {
            let remote = expect_version(stream, max_len, handshake_key).await?;
            let signed = attach_auth(local_version.clone(), handshake_key);
            write_message(stream, &NetMessage::Version(signed))
                .await
                .map_err(map_network_error)?;
            write_message(stream, &NetMessage::VerAck)
                .await
                .map_err(map_network_error)?;
            expect_verack(stream, max_len).await?;
            Ok(remote)
        }
    }
    .map_err(|err| match err {
        HandshakeError::Io(io_err) if io_err.kind() == std::io::ErrorKind::WouldBlock => {
            HandshakeError::Timeout
        }
        other => other,
    })
}

async fn expect_version<S>(
    stream: &mut S,
    max_len: usize,
    handshake_key: &[u8; 32],
) -> Result<Version, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    let msg = timeout(HANDSHAKE_TIMEOUT, read_message(stream, max_len)).await;
    let message = msg
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(map_network_error)?;
    match message {
        NetMessage::Version(version) => {
            validate_version(&version, handshake_key)?;
            Ok(version)
        }
        _ => Err(HandshakeError::UnexpectedMessage),
    }
}

async fn expect_verack<S>(stream: &mut S, max_len: usize) -> Result<(), HandshakeError>
where
    S: AsyncRead + Unpin,
{
    let msg = timeout(HANDSHAKE_TIMEOUT, read_message(stream, max_len)).await;
    let message = msg
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(map_network_error)?;
    match message {
        NetMessage::VerAck => Ok(()),
        _ => Err(HandshakeError::UnexpectedMessage),
    }
}

fn validate_version(version: &Version, handshake_key: &[u8; 32]) -> Result<(), HandshakeError> {
    if version.version == 0 {
        return Err(HandshakeError::VersionMismatch);
    }
    if version.user_agent.len() > 128 {
        return Err(HandshakeError::VersionMismatch);
    }
    if version.auth_tag == [0u8; 32] {
        return Err(HandshakeError::VersionMismatch);
    }
    let expected = compute_auth_tag(version, handshake_key);
    if expected != version.auth_tag {
        return Err(HandshakeError::VersionMismatch);
    }
    Ok(())
}

fn map_network_error(err: NetworkError) -> HandshakeError {
    match err {
        NetworkError::Io(io) => HandshakeError::Io(io),
        NetworkError::Handshake(inner) => inner,
        NetworkError::Capacity | NetworkError::UnknownPeer(_) | NetworkError::FrameTooLarge => {
            HandshakeError::Io(io::Error::new(io::ErrorKind::Other, err))
        }
    }
}

fn attach_auth(mut version: Version, handshake_key: &[u8; 32]) -> Version {
    version.auth_tag = compute_auth_tag(&version, handshake_key);
    version
}

fn compute_auth_tag(version: &Version, handshake_key: &[u8; 32]) -> [u8; 32] {
    let mut canonical = version.clone();
    canonical.auth_tag = [0u8; 32];
    let mut hasher = Hasher::new_keyed(handshake_key);
    hash_version(&mut hasher, &canonical);
    hasher.finalize().into()
}

fn hash_version(hasher: &mut Hasher, version: &Version) {
    hasher.update(&version.version.to_le_bytes());
    hasher.update(&version.services.0.to_le_bytes());
    hasher.update(&version.timestamp.to_le_bytes());
    hash_addr(hasher, &version.receiver);
    hash_addr(hasher, &version.sender);
    hasher.update(&version.nonce.to_le_bytes());
    hasher.update(&(version.user_agent.len() as u64).to_le_bytes());
    hasher.update(version.user_agent.as_bytes());
    hasher.update(&version.best_height.to_le_bytes());
}

fn hash_addr(hasher: &mut Hasher, addr: &NodeAddr) {
    hasher.update(&(addr.address.len() as u64).to_le_bytes());
    hasher.update(addr.address.as_bytes());
    hasher.update(&addr.port.to_le_bytes());
    hasher.update(&addr.services.0.to_le_bytes());
}
