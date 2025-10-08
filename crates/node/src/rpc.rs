use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Json, Router, extract::State, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tracing::info;

use codec::from_slice_cbor;
use p2p::{Inventory, InventoryItem, NetMessage, PeerSummary};
use parking_lot::Mutex;
use tx::{Tx, TxId};

use crate::mempool::{MempoolAddOutcome, MempoolRejection, TxPool};
use crate::state::ChainState;
use p2p::NetworkHandle;

#[derive(Clone)]
pub struct RpcContext {
    mempool: Arc<TxPool>,
    chain: Arc<Mutex<ChainState>>,
    network: NetworkHandle,
}

impl RpcContext {
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

    fn chain_snapshot(&self) -> ChainSnapshot {
        let guard = self.chain.lock();
        ChainSnapshot {
            height: guard.height(),
            best_hash: guard.best_hash(),
        }
    }

    fn peers(&self) -> Vec<PeerSummary> {
        self.network.peer_info()
    }

    fn submit_transaction(&self, tx: Tx, bytes: Vec<u8>) -> Result<TxId, RpcError> {
        let candidate_txid = tx.txid();
        let outcome = self
            .mempool
            .accept_transaction(tx, Some(bytes), |txid, index| {
                let guard = self.chain.lock();
                guard.has_utxo(txid, index)
            });
        match outcome {
            MempoolAddOutcome::Accepted { txid } => {
                self.broadcast_inv(txid);
                Ok(txid)
            }
            MempoolAddOutcome::Duplicate => Ok(candidate_txid),
            MempoolAddOutcome::StoredOrphan { missing } => Err(RpcError::new(
                -26,
                format!(
                    "missing inputs: {}",
                    missing
                        .iter()
                        .map(|out| format!("{}:{}", hex::encode(out.txid), out.index))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
            MempoolAddOutcome::Rejected(reason) => Err(map_rejection(reason)),
        }
    }

    fn broadcast_inv(&self, txid: TxId) {
        let item = InventoryItem::tx(*txid.as_bytes());
        self.network
            .broadcast(NetMessage::Inv(Inventory::single(item)));
    }
}

struct ChainSnapshot {
    height: u64,
    best_hash: [u8; 32],
}

#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
    id: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub async fn spawn_rpc_server(
    ctx: RpcContext,
    listen: SocketAddr,
) -> Result<JoinHandle<()>, anyhow::Error> {
    let router = Router::new()
        .route("/", post(handle_rpc))
        .with_state(Arc::new(ctx));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(%listen, "rpc listening");
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            tracing::error!(error = ?err, "rpc server terminated");
        }
    });
    Ok(handle)
}

async fn handle_rpc(
    State(ctx): State<Arc<RpcContext>>,
    Json(request): Json<RpcRequest>,
) -> impl IntoResponse {
    if request.jsonrpc != "2.0" {
        let error = RpcError::new(-32600, "unsupported jsonrpc version");
        return Json(failure(request.id.clone(), error));
    }

    let response = match request.method.as_str() {
        "getblockcount" => {
            let snapshot = ctx.chain_snapshot();
            success(request.id, json!(snapshot.height))
        }
        "getbestblockhash" => {
            let snapshot = ctx.chain_snapshot();
            success(request.id, json!(hex::encode(snapshot.best_hash)))
        }
        "getrawmempool" => {
            let txids = ctx
                .mempool
                .txids()
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>();
            success(request.id, json!(txids))
        }
        "sendrawtransaction" => match parse_single_param(&request.params) {
            Ok(Value::String(hex_tx)) => match hex::decode(&hex_tx) {
                Ok(bytes) => match from_slice_cbor::<Tx>(&bytes) {
                    Ok(tx) => match ctx.submit_transaction(tx, bytes) {
                        Ok(txid) => success(request.id, json!(txid.to_string())),
                        Err(err) => failure(request.id, err),
                    },
                    Err(err) => failure(
                        request.id,
                        RpcError::new(-22, format!("decode error: {err}")),
                    ),
                },
                Err(err) => failure(
                    request.id,
                    RpcError::new(-22, format!("invalid hex: {err}")),
                ),
            },
            Ok(_) => failure(request.id, RpcError::new(-32602, "expected hex string")),
            Err(err) => failure(request.id, err),
        },
        "getpeerinfo" => {
            let peers = ctx
                .peers()
                .into_iter()
                .map(|peer| {
                    json!({
                        "peerid": peer.peer_id.to_string(),
                        "inbound": peer.inbound,
                        "address": peer.address,
                        "user_agent": peer.user_agent,
                        "best_height": peer.best_height,
                        "services": peer.services.0,
                        "connected_for": peer.connected_at.elapsed().as_secs(),
                    })
                })
                .collect::<Vec<_>>();
            success(request.id, json!(peers))
        }
        "getnetworkinfo" => {
            let version = ctx.network.local_version();
            let peers = ctx.peers();
            let target_spacing = {
                let guard = ctx.chain.lock();
                guard.params().target_spacing
            };
            success(
                request.id,
                json!({
                    "version": version.version,
                    "subversion": version.user_agent,
                    "connections": peers.len(),
                    "target_block_spacing": target_spacing,
                }),
            )
        }
        other => failure(
            request.id,
            RpcError::new(-32601, format!("unknown method {other}")),
        ),
    };
    Json(response)
}

fn parse_single_param(params: &Option<Value>) -> Result<Value, RpcError> {
    match params {
        Some(Value::Array(values)) => values
            .first()
            .cloned()
            .ok_or_else(|| RpcError::new(-32602, "missing parameter")),
        Some(value) => Ok(value.clone()),
        None => Err(RpcError::new(-32602, "missing parameter")),
    }
}

fn success(id: Option<Value>, result: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        result: Some(result),
        error: None,
        id,
    }
}

fn failure(id: Option<Value>, error: RpcError) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        result: None,
        error: Some(error),
        id,
    }
}

fn map_rejection(reason: MempoolRejection) -> RpcError {
    match reason {
        MempoolRejection::PoolFull => RpcError::new(-26, "mempool full"),
        MempoolRejection::DuplicateLinkTag(tag) => {
            RpcError::new(-26, format!("duplicate link tag: {}", hex::encode(tag)))
        }
        MempoolRejection::MissingInputs { missing } => RpcError::new(
            -26,
            format!(
                "missing inputs: {}",
                missing
                    .iter()
                    .map(|out| format!("{}:{}", hex::encode(out.txid), out.index))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        MempoolRejection::OrphanLimit => RpcError::new(-26, "orphan pool full"),
        MempoolRejection::CoinbaseForbidden => {
            RpcError::new(-26, "coinbase transactions not allowed")
        }
    }
}
