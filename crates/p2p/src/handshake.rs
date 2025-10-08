use std::time::Duration;

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::codec::{read_message, write_message};
use crate::error::{HandshakeError, NetworkError};
use crate::types::{NetMessage, Version};

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
) -> Result<Version, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match role {
        PeerRole::Outbound => {
            write_message(stream, &NetMessage::Version(local_version.clone()))
                .await
                .map_err(map_network_error)?;
            let remote = expect_version(stream, max_len).await?;
            validate_version(&remote)?;
            write_message(stream, &NetMessage::VerAck)
                .await
                .map_err(map_network_error)?;
            expect_verack(stream, max_len).await?;
            Ok(remote)
        }
        PeerRole::Inbound => {
            let remote = expect_version(stream, max_len).await?;
            validate_version(&remote)?;
            write_message(stream, &NetMessage::Version(local_version.clone()))
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

async fn expect_version<S>(stream: &mut S, max_len: usize) -> Result<Version, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    let msg = timeout(HANDSHAKE_TIMEOUT, read_message(stream, max_len)).await;
    let message = msg
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(map_network_error)?;
    match message {
        NetMessage::Version(version) => Ok(version),
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

fn validate_version(version: &Version) -> Result<(), HandshakeError> {
    if version.version == 0 {
        return Err(HandshakeError::VersionMismatch);
    }
    if version.user_agent.len() > 128 {
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
