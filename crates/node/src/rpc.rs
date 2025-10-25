#![allow(dead_code)]

use std::fmt::Write as FmtWrite;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tracing::info;

use codec::from_slice_cbor;
use p2p::{Inventory, InventoryItem, NetMessage, PeerSummary};
use parking_lot::Mutex;
use tx::{Tx, TxId};

use crate::mempool::{MempoolAddOutcome, MempoolRejection, TxPool, TxPoolStats};
use crate::metrics::{PrivacyMetrics, StorageMetrics};
use crate::state::{ChainMetrics, ChainState};
use p2p::NetworkHandle;

#[derive(Clone)]
pub struct RpcContext {
    mempool: Arc<Mutex<TxPool>>,
    chain: Arc<Mutex<ChainState>>,
    network: Arc<Mutex<NetworkHandle>>,
    storage_metrics: Arc<StorageMetrics>,
    privacy_metrics: Arc<PrivacyMetrics>,
}

impl RpcContext {
    pub fn new(
        mempool: Arc<Mutex<TxPool>>,
        chain: Arc<Mutex<ChainState>>,
        network: NetworkHandle,
        storage_metrics: Arc<StorageMetrics>,
        privacy_metrics: Arc<PrivacyMetrics>,
    ) -> Self {
        Self {
            mempool,
            chain,
            network: Arc::new(Mutex::new(network)),
            storage_metrics,
            privacy_metrics,
        }
    }

    pub fn storage_metrics(&self) -> &StorageMetrics {
        &self.storage_metrics
    }

    pub fn privacy_metrics(&self) -> &PrivacyMetrics {
        &self.privacy_metrics
    }

    fn chain_snapshot(&self) -> ChainSnapshot {
        let guard = self.chain.lock();
        ChainSnapshot {
            height: guard.height(),
            best_hash: guard.best_hash(),
        }
    }

    fn peers(&self) -> Vec<PeerSummary> {
        self.network.lock().peer_info()
    }

    fn metrics_snapshot(&self) -> MetricsSnapshot {
        let (chain_metrics, db_stats) = {
            let guard = self.chain.lock();
            (guard.metrics(), guard.db_stats())
        };
        MetricsSnapshot {
            chain: chain_metrics,
            mempool: self.mempool.lock().stats(),
            peer_count: self.peers().len(),
            running_compactions: db_stats.running_compactions,
        }
    }

    fn render_metrics(&self) -> String {
        let snapshot = self.metrics_snapshot();

        // Storage metrics are updated by background task, just read cached values
        let mut body = String::new();
        let _ = writeln!(body, "pqpriv_peers {}", snapshot.peer_count);
        let _ = writeln!(body, "pqpriv_tip_height {}", snapshot.chain.height);
        let _ = writeln!(
            body,
            "pqpriv_cumulative_work {}",
            snapshot.chain.cumulative_work_f64()
        );
        let _ = writeln!(
            body,
            "pqpriv_current_target {}",
            snapshot.chain.current_target
        );
        let _ = writeln!(body, "pqpriv_mempool_size {}", snapshot.mempool.tx_count);
        let _ = writeln!(
            body,
            "pqpriv_mempool_bytes {}",
            snapshot.mempool.total_bytes
        );
        let _ = writeln!(
            body,
            "pqpriv_orphan_count {}",
            snapshot.mempool.orphan_count
        );
        let _ = writeln!(
            body,
            "pqpriv_db_compactions {}",
            snapshot.running_compactions
        );
        let _ = writeln!(body, "pqpriv_reorg_count {}", snapshot.chain.reorg_count);
        let _ = writeln!(
            body,
            "pqpriv_batch_commit_ms {:.3}",
            snapshot.chain.last_commit_ms
        );

        // Storage metrics from RocksDB (now updated with live DB stats)
        body.push_str(&self.storage_metrics.to_prometheus());

        // Privacy metrics from confidential transaction validation
        body.push_str(&self.privacy_metrics.to_prometheus());

        body
    }

    fn submit_transaction(&self, tx: Tx, bytes: Vec<u8>) -> Result<TxId, RpcError> {
        let candidate_txid = tx.txid();
        let outcome = self.mempool.lock().accept_transaction(
            tx,
            Some(bytes),
            |txid, index| {
                let guard = self.chain.lock();
                guard.has_utxo(txid, index)
            },
            self.chain.lock().params().stark_enabled,
            |nullifier| {
                let guard = self.chain.lock();
                guard.has_nullifier(nullifier)
            },
        );
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
            .lock()
            .broadcast(NetMessage::Inv(Inventory::single(item)));
    }
}

struct ChainSnapshot {
    height: u64,
    best_hash: [u8; 32],
}

struct MetricsSnapshot {
    chain: ChainMetrics,
    mempool: TxPoolStats,
    peer_count: usize,
    running_compactions: u64,
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
    ctx: Arc<RpcContext>,
    listen: SocketAddr,
) -> Result<(JoinHandle<()>, SocketAddr), anyhow::Error> {
    let router = Router::new()
        .route("/", post(handle_rpc))
        .route("/metrics", get(handle_metrics))
        .route("/health", get(handle_health))
        .route("/chain/tip", get(handle_chain_tip));

    #[cfg(feature = "devnet")]
    let router = router.route("/dev/mine", post(handle_dev_mine));

    let router = router.with_state(ctx);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let actual_addr = listener.local_addr()?;
    info!(addr = %actual_addr, "rpc listening");
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            tracing::error!(error = ?err, "rpc server terminated");
        }
    });
    Ok((handle, actual_addr))
}

async fn handle_health(State(_ctx): State<Arc<RpcContext>>) -> impl IntoResponse {
    Json(json!({
        "status": "ok"
    }))
}

async fn handle_chain_tip(State(ctx): State<Arc<RpcContext>>) -> impl IntoResponse {
    let snapshot = ctx.chain_snapshot();
    Json(json!({
        "height": snapshot.height,
        "hash": hex::encode(snapshot.best_hash)
    }))
}

#[cfg(feature = "devnet")]
async fn handle_dev_mine(State(ctx): State<Arc<RpcContext>>) -> impl IntoResponse {
    use consensus::{BlockHeader, merkle_root, pow_hash};
    use pow::mine_block;

    let (params, prev_hash, height, n_bits) = {
        let guard = ctx.chain.lock();
        let tip = guard.tip();
        let next_bits = guard.next_difficulty_bits().unwrap_or(tip.header.n_bits);
        (
            guard.params().clone(),
            pow_hash(&tip.header),
            guard.height() + 1,
            next_bits,
        )
    };

    let material = crypto::KeyMaterial::random();
    let tx = build_coinbase_tx(&material, height);
    let txs = vec![tx];

    let header = BlockHeader {
        version: 1,
        prev_hash,
        merkle_root: merkle_root(&txs),
        utxo_root: [0u8; 32],
        time: current_time() + height, // Ensure time advances for each block
        n_bits,
        nonce: 0,
        alg_tag: 1,
    };

    let block = mine_block(header, txs, &params.pow_limit);

    let result = {
        let mut guard = ctx.chain.lock();
        guard.apply_block(block)
    };

    match result {
        Ok(_) => Json(json!({
            "height": height,
            "status": "mined"
        })),
        Err(err) => Json(json!({
            "error": format!("{}", err)
        })),
    }
}

#[cfg(feature = "devnet")]
fn build_coinbase_tx(material: &crypto::KeyMaterial, height: u64) -> tx::Tx {
    use tx::{Output, OutputMeta, TxBuilder, Witness, build_stealth_blob};

    let scan = material.derive_scan_keypair(0);
    let spend = material.derive_spend_keypair(0);
    let stealth = build_stealth_blob(&scan.public, &spend.public, &height.to_le_bytes());
    let output = Output::new(stealth, 50, OutputMeta::default());

    TxBuilder::new()
        .add_output(output)
        .set_witness(Witness::new(Vec::new(), current_time(), Vec::new()))
        .build()
}

#[cfg(feature = "devnet")]
fn current_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn handle_metrics(State(ctx): State<Arc<RpcContext>>) -> String {
    ctx.render_metrics()
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
                .lock()
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
            let version = ctx.network.lock().local_version();
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
        MempoolRejection::FeeTooLow { required, actual } => RpcError::new(
            -26,
            format!(
                "fee too low: required {} sat/vb, actual {}",
                required, actual
            ),
        ),
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
        MempoolRejection::StarkNotEnabled => {
            RpcError::new(-26, "TX v2 rejected: STARK privacy feature not enabled")
        }
        MempoolRejection::DuplicateNullifier(nullifier) => RpcError::new(
            -26,
            format!(
                "duplicate nullifier (double-spend): {}",
                hex::encode(nullifier)
            ),
        ),
        MempoolRejection::InvalidAnonymitySetSize { actual } => RpcError::new(
            -26,
            format!("invalid anonymity set size: {} (expected 32-256)", actual),
        ),
        MempoolRejection::TooManyPendingV2 { limit } => RpcError::new(
            -26,
            format!(
                "too many pending TX v2 transactions (DoS protection, limit: {})",
                limit
            ),
        ),
        MempoolRejection::InsufficientStarkFee { required, actual } => RpcError::new(
            -26,
            format!(
                "insufficient fee for STARK verification: required {} sat/vb, actual {}",
                required, actual
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::{TxPool, TxPoolConfig};
    use crate::state::ChainState;
    use consensus::{Block, BlockHeader, ChainParams, merkle_root};
    use crypto::KeyMaterial;
    use p2p::{P2pConfig, Version, start_network};
    use parking_lot::Mutex;
    use pow::mine_block;
    use std::sync::Arc;
    use storage::Store;
    use tempfile::tempdir;
    use tx::{Output, OutputMeta, TxBuilder, Witness, build_stealth_blob};

    fn build_block(prev_hash: [u8; 32], seed: u64, params: &ChainParams) -> Block {
        let tx = coinbase(seed);
        let txs = vec![tx.clone()];
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: merkle_root(&txs),
            utxo_root: [0u8; 32],
            time: seed,
            n_bits: 0x207fffff,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, txs, &params.pow_limit)
    }

    fn coinbase(seed: u64) -> tx::Tx {
        let material = KeyMaterial::random();
        let scan = material.derive_scan_keypair(0);
        let spend = material.derive_spend_keypair(0);
        let stealth = build_stealth_blob(&scan.public, &spend.public, &seed.to_le_bytes());
        TxBuilder::new()
            .add_output(Output::new(
                stealth,
                50,
                OutputMeta {
                    deposit_flag: false,
                    deposit_id: None,
                },
            ))
            .set_witness(Witness::new(Vec::new(), seed, Vec::new()))
            .build()
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_expected_gauges() {
        let params = ChainParams::default();
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let genesis = build_block([0u8; 32], 0, &params);
        let chain = ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap");
        let chain = Arc::new(Mutex::new(chain));
        let mempool = Arc::new(Mutex::new(TxPool::new(TxPoolConfig::default())));
        let config = P2pConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let version = Version::user_agent("test", 0);
        let network = start_network(config, version).await.expect("start network");
        let storage_metrics = Arc::new(StorageMetrics::new());
        let privacy_metrics = Arc::new(PrivacyMetrics::new());
        let ctx = Arc::new(RpcContext::new(
            mempool,
            chain,
            network,
            storage_metrics,
            privacy_metrics,
        ));
        let body = handle_metrics(State(ctx)).await;
        for metric in [
            "pqpriv_peers",
            "pqpriv_tip_height",
            "pqpriv_cumulative_work",
            "pqpriv_current_target",
            "pqpriv_mempool_size",
            "pqpriv_orphan_count",
            "pqpriv_db_compactions",
            "pqpriv_reorg_count",
            "pqpriv_batch_commit_ms",
        ] {
            assert!(body.contains(metric), "missing metric {metric}");
        }
    }
}
