use std::sync::Arc;

use codec::from_slice_cbor;
use consensus::{Block, BlockHeader};
use p2p::{InvType, Inventory, InventoryItem, NetMessage, PeerId};
use tracing::{debug, warn};
use tx::{Tx, TxId};

use crate::mempool::{MempoolAddOutcome, MempoolRejection, TxPool};
use crate::state::ChainState;
use crate::sync::SyncManager;
use p2p::NetworkHandle;
use parking_lot::Mutex;

#[derive(Clone)]
pub struct Relay {
    mempool: Arc<Mutex<TxPool>>,
    chain: Arc<Mutex<ChainState>>,
    network: NetworkHandle,
    sync: Arc<SyncManager>,
}

impl Relay {
    pub fn new(
        mempool: Arc<Mutex<TxPool>>,
        chain: Arc<Mutex<ChainState>>,
        network: NetworkHandle,
        sync: Arc<SyncManager>,
    ) -> Self {
        {
            let mut guard = chain.lock();
            guard.attach_mempool(Arc::clone(&mempool));
        }
        Self {
            mempool,
            chain,
            network,
            sync,
        }
    }

    pub fn handle_inv(&self, peer_id: PeerId, inventory: Inventory) {
        debug!(peer = %peer_id, items = inventory.items.len(), "received inv");
        let mut tx_requests = Vec::new();
        let mut block_candidates = Vec::new();
        {
            let chain = self.chain.lock();
            for item in inventory.items {
                match item.kind {
                    InvType::Transaction => {
                        let txid = TxId(item.hash);
                        if !self.mempool.lock().contains(&txid) {
                            tx_requests.push(InventoryItem::tx(*txid.as_bytes()));
                        }
                    }
                    InvType::Block => {
                        if chain.has_block(&item.hash) {
                            continue;
                        }
                        block_candidates.push(item);
                    }
                }
            }
        }

        debug!(peer = %peer_id, tx_requests = tx_requests.len(), block_requests = block_candidates.len(), "prepared getdata");

        if !tx_requests.is_empty() {
            let _ = self.network.send(
                peer_id,
                NetMessage::GetData(Inventory { items: tx_requests }),
            );
        }

        if !block_candidates.is_empty() {
            let filtered = self.sync.filter_inventory(&Inventory {
                items: block_candidates,
            });
            if !filtered.items.is_empty() {
                debug!(peer = %peer_id, blocks = filtered.items.len(), "sending getdata for blocks");
                let _ = self.network.send(peer_id, NetMessage::GetData(filtered));
            }
        }
    }

    pub fn handle_headers(&self, peer_id: PeerId, headers: Vec<BlockHeader>) {
        if headers.is_empty() {
            return;
        }
        debug!(peer = %peer_id, count = headers.len(), "received headers");
        let requests = {
            let chain = self.chain.lock();
            self.sync.register_headers(&headers, &chain)
        };
        if requests.is_empty() {
            debug!(peer = %peer_id, "no new blocks needed from headers");
            return;
        }
        debug!(peer = %peer_id, count = requests.len(), "requesting blocks from headers");
        let items = requests.into_iter().map(InventoryItem::block).collect();
        let _ = self
            .network
            .send(peer_id, NetMessage::GetData(Inventory { items }));
    }

    pub fn handle_get_data(&self, peer_id: PeerId, inventory: Inventory) {
        for item in inventory.items {
            match item.kind {
                InvType::Transaction => {
                    let txid = TxId(item.hash);
                    if let Some(bytes) = self.mempool.lock().get_bytes(&txid) {
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
        debug!(peer = %peer_id, locator_len = locator.len(), "received GetHeaders");
        let headers = {
            let chain = self.chain.lock();
            chain.headers_for_locator(&locator, stop.as_ref(), 2000)
        };
        if !headers.is_empty() {
            debug!(peer = %peer_id, count = headers.len(), "sending Headers response");
            let _ = self.network.send(peer_id, NetMessage::Headers(headers));
        } else {
            debug!(peer = %peer_id, "no headers to send");
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

    pub fn handle_block(&self, peer_id: PeerId, bytes: Vec<u8>) {
        match from_slice_cbor::<Block>(&bytes) {
            Ok(block) => {
                let block_hash = consensus::pow_hash(&block.header);
                debug!(peer = %peer_id, hash = ?block_hash, "received block");
                let mut chain = self.chain.lock();
                match self.sync.process_block(block, &mut chain) {
                    Ok(applied) => {
                        if !applied.is_empty() {
                            debug!(applied = applied.len(), "applied blocks to chain");
                            let items = applied.into_iter().map(InventoryItem::block).collect();
                            self.network.broadcast_except(
                                NetMessage::Inv(Inventory { items }),
                                Some(peer_id),
                            );
                        }
                    }
                    Err(err) => warn!(%peer_id, error = ?err, "block rejected"),
                }
            }
            Err(err) => warn!(%peer_id, error = ?err, "failed to decode block"),
        }
    }

    pub fn broadcast_inv(&self, txid: TxId, skip: Option<PeerId>) {
        let item = InventoryItem::tx(*txid.as_bytes());
        self.network
            .broadcast_except(NetMessage::Inv(Inventory::single(item)), skip);
    }

    pub fn network(&self) -> NetworkHandle {
        self.network.clone()
    }

    fn admit_transaction(&self, tx: Tx, bytes: Vec<u8>) -> Result<TxId, MempoolRejection> {
        let txid = tx.txid();
        let outcome = self
            .mempool
            .lock()
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
