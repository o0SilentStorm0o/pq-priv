//! Minimal peer-to-peer networking stack for PQ-PRIV testnets.
//!
//! The implementation focuses on deterministic framing, a Bitcoin-inspired
//! message set, and lightweight peer management that can be embedded in the
//! reference node.

mod codec;
mod config;
mod error;
mod handshake;
mod inventory;
mod peer;
mod peerman;
mod router;
mod types;

pub use config::P2pConfig;
pub use error::{HandshakeError, NetworkError};
pub use inventory::InventoryRegistry;
pub use peerman::{NetworkHandle, start_network};
pub use router::{PeerEvent, PeerSummary};
pub use types::{
    InvType, Inventory, InventoryItem, NetMessage, NodeAddr, PeerId, Services, Version,
};
