use std::io;

use thiserror::Error;

use crate::types::PeerId;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("maximum peers reached")]
    Capacity,
    #[error("peer {0} not found")]
    UnknownPeer(PeerId),
    #[error("message too large")]
    FrameTooLarge,
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("unexpected message type")]
    UnexpectedMessage,
    #[error("version mismatch")]
    VersionMismatch,
    #[error("timed out waiting for handshake")]
    Timeout,
}

impl From<NetworkError> for io::Error {
    fn from(err: NetworkError) -> Self {
        match err {
            NetworkError::Io(e) => e,
            other => io::Error::other(other),
        }
    }
}
