use std::fmt;

use consensus::BlockHeader;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

/// Unique identifier assigned to each connected peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub u64);

impl PeerId {
    pub fn random() -> Self {
        let mut rng = OsRng;
        Self(rng.next_u64())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Bitmask describing peer service capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Services(pub u64);

impl Services {
    pub const NODE_NETWORK: Services = Services(1 << 0);
}

impl Default for Services {
    fn default() -> Self {
        Services::NODE_NETWORK
    }
}

/// Network address advertised in handshake messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAddr {
    pub address: String,
    pub port: u16,
    pub services: Services,
}

impl NodeAddr {
    pub fn new(address: String, port: u16, services: Services) -> Self {
        Self {
            address,
            port,
            services,
        }
    }
}

/// Version handshake describing peer properties.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub version: u32,
    pub services: Services,
    pub timestamp: i64,
    pub receiver: NodeAddr,
    pub sender: NodeAddr,
    pub nonce: u64,
    pub user_agent: String,
    pub best_height: u64,
    #[serde(with = "serde_bytes")]
    pub auth_tag: [u8; 32],
}

impl Version {
    pub fn user_agent(agent: impl Into<String>, best_height: u64) -> Self {
        let services = Services::default();
        Self {
            version: 1,
            services,
            timestamp: chrono::Utc::now().timestamp(),
            receiver: NodeAddr::new("0.0.0.0".to_string(), 0, services),
            sender: NodeAddr::new("0.0.0.0".to_string(), 0, services),
            nonce: OsRng.next_u64(),
            user_agent: agent.into(),
            best_height,
            auth_tag: [0u8; 32],
        }
    }
}

/// Inventory announcement payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub items: Vec<InventoryItem>,
}

impl Inventory {
    pub fn single(item: InventoryItem) -> Self {
        Self { items: vec![item] }
    }
}

/// Inventory entry identifying a transaction or block.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InventoryItem {
    pub kind: InvType,
    pub hash: [u8; 32],
}

impl InventoryItem {
    pub fn tx(hash: [u8; 32]) -> Self {
        Self {
            kind: InvType::Transaction,
            hash,
        }
    }

    pub fn block(hash: [u8; 32]) -> Self {
        Self {
            kind: InvType::Block,
            hash,
        }
    }
}

/// Enumerates data types referenced by an inventory item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvType {
    Transaction = 1,
    Block = 2,
}

/// Top-level wire messages exchanged across peers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetMessage {
    Version(Version),
    VerAck,
    GetHeaders {
        locator: Vec<[u8; 32]>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stop_hash: Option<[u8; 32]>,
    },
    Headers(Vec<BlockHeader>),
    Ping(u64),
    Pong(u64),
    GetAddr,
    Addr(Vec<NodeAddr>),
    Inv(Inventory),
    GetData(Inventory),
    Tx(#[serde(with = "serde_bytes")] Vec<u8>),
    Block(#[serde(with = "serde_bytes")] Vec<u8>),
    Reject {
        code: u16,
        reason: String,
    },
}
