mod cfg;
mod mempool;
mod relay;
mod rpc;
mod state;
mod sync;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use consensus::{Block, BlockHeader, ChainParams, pow_hash};
use crypto::{self, KeyMaterial};
use mempool::TxPool;
use p2p::{
    Inventory, InventoryItem, NetMessage, NetworkHandle, NodeAddr, P2pConfig, PeerEvent, Services,
    Version, start_network,
};
use pow::mine_block;
use relay::Relay;
use rpc::{RpcContext, spawn_rpc_server};
use state::{ChainError, ChainState};
use sync::SyncManager;
use tracing::{error, info, warn};
use tx::{Output, OutputMeta, Tx, TxBuilder, Witness, build_stealth_blob};

use crate::cfg::NodeConfig;

#[derive(Parser)]
#[command(author, version, about = "PQ-PRIV reference node prototype")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run(RunArgs),
    Keygen,
}

#[derive(Args)]
struct RunArgs {
    #[arg(long, default_value = "127.0.0.1:8644")]
    p2p_listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:8645")]
    rpc_listen: SocketAddr,
    #[arg(long, value_name = "HOST:PORT")]
    seed: Vec<SocketAddr>,
    #[arg(long, default_value_t = 0)]
    blocks: u32,
    #[arg(long, default_value_t = 50_000_000)]
    mempool_bytes: usize,
    #[arg(long, default_value_t = 64)]
    max_orphans: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => run_node(args).await?,
        Commands::Keygen => {
            let material = KeyMaterial::random();
            info!(
                "seed" = hex::encode(material.derive_view_token("seed").tag),
                "Generated placeholder seed"
            );
        }
    }
    Ok(())
}

async fn run_node(args: RunArgs) -> Result<()> {
    let config = NodeConfig::new(
        args.p2p_listen,
        args.rpc_listen,
        args.seed,
        args.mempool_bytes,
        args.max_orphans,
        args.blocks,
    );

    let params = ChainParams::default();
    let genesis = genesis_block();
    let chain = Arc::new(parking_lot::Mutex::new(ChainState::bootstrap(
        params,
        genesis.clone(),
    )?));
    let mempool = Arc::new(TxPool::new(config.max_mempool_bytes, config.max_orphans));

    let version = Version::user_agent(
        format!("pq-priv/{}", env!("CARGO_PKG_VERSION")),
        chain.lock().height(),
    );
    let mut p2p_config = P2pConfig::default();
    p2p_config.listen = config.p2p_listen;
    p2p_config.seeds = config.seeds.clone();
    let mut local_version = version.clone();
    local_version.sender = NodeAddr::new(
        config.p2p_listen.ip().to_string(),
        config.p2p_listen.port(),
        Services::NODE_NETWORK,
    );
    local_version.receiver = local_version.sender.clone();
    let network = start_network(p2p_config, local_version).await?;

    let relay = Relay::new(mempool.clone(), chain.clone(), network.clone());
    let sync_manager = SyncManager::new();
    sync_manager.mark_known(pow_hash(&genesis.header));

    let rpc_handle = spawn_rpc_server(
        RpcContext::new(mempool.clone(), chain.clone(), network.clone()),
        config.rpc_listen,
    )
    .await?;

    let mut events = network.subscribe();

    if config.blocks > 0 {
        let relay_clone = relay.clone();
        let chain_clone = chain.clone();
        let mempool_clone = mempool.clone();
        let network_clone = network.clone();
        tokio::spawn(async move {
            if let Err(err) = mine_blocks(
                config.blocks,
                chain_clone,
                mempool_clone,
                network_clone,
                relay_clone,
            )
            .await
            {
                error!(?err, "mining loop failed");
            }
        });
    }

    loop {
        match events.recv().await {
            Ok(PeerEvent::Connected(info)) => {
                info!(peer = %info.peer_id, inbound = info.inbound, "peer connected");
            }
            Ok(PeerEvent::Disconnected { peer_id, reason }) => {
                info!(%peer_id, %reason, "peer disconnected");
            }
            Ok(PeerEvent::Message { peer_id, message }) => {
                handle_message(
                    &relay,
                    &sync_manager,
                    &mempool,
                    &chain,
                    &network,
                    peer_id,
                    message,
                )
                .await;
            }
            Err(err) => {
                error!(?err, "peer event channel closed");
                break;
            }
        }
    }

    rpc_handle.abort();
    Ok(())
}

async fn handle_message(
    relay: &Relay,
    sync_manager: &SyncManager,
    mempool: &Arc<TxPool>,
    chain: &Arc<parking_lot::Mutex<ChainState>>,
    network: &NetworkHandle,
    peer_id: p2p::PeerId,
    message: NetMessage,
) {
    match message {
        NetMessage::Ping(nonce) => {
            let _ = network.send(peer_id, NetMessage::Pong(nonce));
        }
        NetMessage::Pong(_) => {}
        NetMessage::Inv(inventory) => {
            let filtered = sync_manager.filter_inventory(&inventory);
            if !filtered.items.is_empty() {
                relay.handle_inv(peer_id, filtered);
            }
        }
        NetMessage::GetData(inventory) => {
            relay.handle_get_data(peer_id, inventory);
        }
        NetMessage::Tx(bytes) => {
            relay.handle_tx(peer_id, bytes);
        }
        NetMessage::Block(bytes) => match codec::from_slice_cbor::<Block>(&bytes) {
            Ok(block) => {
                if let Err(err) =
                    apply_block_from_network(&block, chain, mempool, relay, network, sync_manager)
                        .await
                {
                    warn!(%peer_id, error = ?err, "failed to apply network block");
                }
            }
            Err(err) => warn!(%peer_id, error = ?err, "failed to decode block"),
        },
        NetMessage::GetAddr => {
            let _ = network.send(peer_id, NetMessage::Addr(Vec::new()));
        }
        NetMessage::Addr(_)
        | NetMessage::Reject { .. }
        | NetMessage::Version(_)
        | NetMessage::VerAck => {}
    }
}

async fn apply_block_from_network(
    block: &Block,
    chain: &Arc<parking_lot::Mutex<ChainState>>,
    mempool: &Arc<TxPool>,
    relay: &Relay,
    network: &NetworkHandle,
    sync_manager: &SyncManager,
) -> Result<(), ChainError> {
    let mut guard = chain.lock();
    guard.apply_block(block.clone())?;
    let txids: Vec<_> = block.txs.iter().skip(1).map(|tx| tx.txid()).collect();
    sync_manager.mark_known(pow_hash(&block.header));
    drop(guard);
    mempool.remove_confirmed(&txids);
    for (txid, _bytes) in mempool.resolve_orphans(|txid, index| chain.lock().has_utxo(txid, index))
    {
        relay.broadcast_inv(txid, None);
    }
    let block_hash = pow_hash(&block.header);
    network.broadcast(NetMessage::Inv(Inventory::single(InventoryItem::block(
        block_hash,
    ))));
    network.update_best_height(chain.lock().height());
    Ok(())
}

async fn mine_blocks(
    target: u32,
    chain: Arc<parking_lot::Mutex<ChainState>>,
    mempool: Arc<TxPool>,
    network: NetworkHandle,
    _relay: Relay,
) -> Result<(), ChainError> {
    for _ in 0..target {
        let (prev_block, height) = {
            let guard = chain.lock();
            (guard.tip().clone(), guard.height())
        };
        let txs = vec![coinbase_tx(height + 1)];
        let mut header = block_template(&prev_block);
        header.merkle_root = compute_merkle_root(&txs);
        let block = mine_block(header, txs);
        {
            let mut guard = chain.lock();
            guard.apply_block(block.clone())?;
            info!(height = guard.height(), hash = ?pow_hash(&block.header), "Mined block");
        }
        network.update_best_height(chain.lock().height());
        let block_hash = pow_hash(&block.header);
        let item = InventoryItem::block(block_hash);
        network.broadcast(NetMessage::Inv(Inventory::single(item)));
        mempool.remove_confirmed(&[]);
        let bytes = codec::to_vec_cbor(&block)?;
        network.broadcast(NetMessage::Block(bytes));
    }
    Ok(())
}

fn block_template(prev: &Block) -> BlockHeader {
    let prev_hash = pow_hash(&prev.header);
    BlockHeader {
        version: 1,
        prev_hash,
        merkle_root: [0u8; 32],
        utxo_root: [0u8; 32],
        time: current_time(),
        n_bits: 0x207fffff,
        nonce: 0,
        alg_tag: 1,
    }
}

fn coinbase_tx(height: u64) -> Tx {
    let material = KeyMaterial::random();
    let scan = material.derive_scan_keypair(0);
    let spend = material.derive_spend_keypair(0);
    let stealth = build_stealth_blob(&scan.public, &spend.public, &height.to_le_bytes());
    let commitment = crypto::commitment(50, &height.to_le_bytes());
    let output = Output::new(stealth, commitment, OutputMeta::default());
    TxBuilder::new()
        .add_output(output)
        .set_witness(Witness {
            range_proofs: Vec::new(),
            stamp: current_time(),
            extra: Vec::new(),
        })
        .build()
}

fn compute_merkle_root(txs: &[Tx]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for tx in txs {
        hasher.update(tx.txid().as_bytes());
    }
    hasher.finalize().into()
}

fn genesis_block() -> Block {
    let tx = coinbase_tx(0);
    let header = BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        merkle_root: compute_merkle_root(&[tx.clone()]),
        utxo_root: [0u8; 32],
        time: current_time(),
        n_bits: 0x207fffff,
        nonce: 0,
        alg_tag: 1,
    };
    Block {
        header,
        txs: vec![tx],
    }
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
