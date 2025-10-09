use std::sync::Arc;

use codec::from_slice_cbor;
use p2p::{InvType, Inventory, InventoryItem, NetMessage, PeerId};
use tracing::{debug, warn};
use tx::{Tx, TxId};

use crate::mempool::{MempoolAddOutcome, MempoolRejection, TxPool};
use crate::state::ChainState;
use p2p::NetworkHandle;
use parking_lot::Mutex;

#[derive(Clone)]
pub struct Relay {
    mempool: Arc<TxPool>,
    chain: Arc<Mutex<ChainState>>,
    network: NetworkHandle,
}

impl Relay {
    pub fn new(
        mempool: Arc<TxPool>,
        chain: Arc<Mutex<ChainState>>,
        network: NetworkHandle,
    ) -> Self {
        Self {
            mempool,
            chain,
            network,
        }
    }

    pub fn handle_inv(&self, peer_id: PeerId, inventory: Inventory) {
        let mut to_request = Vec::new();
        for item in inventory.items {
            match item.kind {
                InvType::Transaction => {
                    let txid = TxId(item.hash);
                    if !self.mempool.contains(&txid) {
                        to_request.push(item);
                    }
                }
                InvType::Block => {
                    let known = {
                        let chain = self.chain.lock();
                        chain.has_block(&item.hash)
                    };
                    if !known {
                        to_request.push(item);
                    }
                }
            }
        }
        if !to_request.is_empty() {
            let _ = self.network.send(
                peer_id,
                NetMessage::GetData(Inventory { items: to_request }),
            );
        }
    }

    pub fn handle_get_data(&self, peer_id: PeerId, inventory: Inventory) {
        for item in inventory.items {
            match item.kind {
                InvType::Transaction => {
                    let txid = TxId(item.hash);
                    if let Some(bytes) = self.mempool.get_bytes(&txid) {
                        let _ = self.network.send(peer_id, NetMessage::Tx(bytes));
                    }
                }
                InvType::Block => {
                    let maybe_block = {
                        let chain = self.chain.lock();
                        chain.block_bytes(&item.hash)
                    };
                    if let Some(bytes) = maybe_block {
                        let _ = self.network.send(peer_id, NetMessage::Block(bytes));
                    }
                }
            }
        }
    }

    pub fn handle_get_headers(
        &self,
        peer_id: PeerId,
        locator: Vec<[u8; 32]>,
        stop: Option<[u8; 32]>,
    ) {
        let headers = {
            let chain = self.chain.lock();
            chain.headers_for_locator(&locator, stop.as_ref(), 2000)
        };
        if !headers.is_empty() {
            let _ = self.network.send(peer_id, NetMessage::Headers(headers));
        }
    }

    pub fn handle_tx(&self, peer_id: PeerId, bytes: Vec<u8>) {
        match from_slice_cbor::<Tx>(&bytes) {
            Ok(tx) => match self.admit_transaction(tx, bytes) {
                Ok(txid) => {
                    debug!(%peer_id, %txid, "accepted transaction from peer");
                    self.broadcast_inv(txid, Some(peer_id));
                }
                Err(err) => {
                    warn!(%peer_id, error = ?err, "transaction rejected");
                }
            },
            Err(err) => {
                warn!(%peer_id, error = ?err, "failed to decode transaction from peer");
            }
        }
    }

    pub fn broadcast_inv(&self, txid: TxId, skip: Option<PeerId>) {
        let item = InventoryItem::tx(*txid.as_bytes());
        self.network
            .broadcast_except(NetMessage::Inv(Inventory::single(item)), skip);
    }

    fn admit_transaction(&self, tx: Tx, bytes: Vec<u8>) -> Result<TxId, MempoolRejection> {
        let txid = tx.txid();
        let outcome = self
            .mempool
            .accept_transaction(tx, Some(bytes), |txid, index| {
                let chain = self.chain.lock();
                chain.has_utxo(txid, index)
            });
        match outcome {
            MempoolAddOutcome::Accepted { txid } => Ok(txid),
            MempoolAddOutcome::Duplicate => Ok(txid),
            MempoolAddOutcome::StoredOrphan { missing } => {
                Err(MempoolRejection::MissingInputs { missing })
            }
            MempoolAddOutcome::Rejected(reason) => Err(reason),
        }
    }
}
