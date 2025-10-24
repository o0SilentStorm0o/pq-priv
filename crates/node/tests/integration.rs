use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use consensus::{Block, BlockHeader, ChainParams, merkle_root, pow_hash};
use node::{
    ChainState, Relay, RpcContext, SyncManager, TxPool, TxPoolConfig, run_block_sync_task,
    run_chain_event_loop, run_peer_event_loop, spawn_rpc_server,
};
use p2p::{
    Inventory, InventoryItem, NetMessage, NetworkHandle, NodeAddr, P2pConfig, Services, Version,
    start_network,
};
use parking_lot::Mutex;
use pow::mine_block;
use reqwest::Client;
use storage::{SnapshotConfig, Store};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tx::{Output, OutputMeta, Tx, TxBuilder, Witness, build_stealth_blob};

const GENESIS_TIME: u64 = 1_000;
const SNAPSHOT_INTERVAL: u64 = 5;
const SNAPSHOT_KEEP: usize = 2;
const WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

struct NodeOptions {
    listen: SocketAddr,
    seeds: Vec<SocketAddr>,
    rpc: Option<SocketAddr>,
    db_path: PathBuf,
    snapshots_path: PathBuf,
}

impl NodeOptions {
    fn new(
        listen: SocketAddr,
        seeds: Vec<SocketAddr>,
        db_path: &Path,
        snapshots_path: &Path,
        rpc: Option<SocketAddr>,
    ) -> Self {
        Self {
            listen,
            seeds,
            rpc,
            db_path: db_path.to_path_buf(),
            snapshots_path: snapshots_path.to_path_buf(),
        }
    }
}

struct TestNode {
    chain: Arc<Mutex<ChainState>>,
    sync: Arc<SyncManager>,
    _mempool: Arc<Mutex<TxPool>>,
    network: NetworkHandle,
    peer_task: JoinHandle<()>,
    chain_task: JoinHandle<()>,
    sync_task: JoinHandle<()>,
    rpc_task: Option<JoinHandle<()>>,
}

impl TestNode {
    async fn spawn(params: ChainParams, genesis: Block, options: NodeOptions) -> Self {
        fs::create_dir_all(&options.db_path).expect("db directory");
        fs::create_dir_all(&options.snapshots_path).expect("snapshot directory");

        let store = Store::open(&options.db_path).expect("open store");
        let mut chain_state =
            ChainState::bootstrap(params.clone(), store, genesis).expect("bootstrap chain");
        chain_state
            .configure_snapshots(SnapshotConfig::new(
                options.snapshots_path.clone(),
                SNAPSHOT_INTERVAL,
                SNAPSHOT_KEEP,
            ))
            .expect("configure snapshots");

        let chain = Arc::new(Mutex::new(chain_state));
        let mempool = Arc::new(Mutex::new(TxPool::new(TxPoolConfig::default())));
        let sync = Arc::new(SyncManager::new(4_096, Duration::from_secs(120)));

        {
            let guard = chain.lock();
            sync.mark_known(pow_hash(&guard.tip().header));
        }

        let p2p_config = P2pConfig {
            listen: options.listen,
            seeds: options.seeds.clone(),
            outbound_queue: 8_192,
            ..Default::default()
        };

        let (height, listen_addr) = {
            let guard = chain.lock();
            (guard.height(), p2p_config.listen)
        };
        let mut version = Version::user_agent("node-integration-test", height);
        let advertised = NodeAddr::new(
            listen_addr.ip().to_string(),
            listen_addr.port(),
            Services::NODE_NETWORK,
        );
        version.receiver = advertised.clone();
        version.sender = advertised;

        let network = start_network(p2p_config, version)
            .await
            .expect("start network");
        let relay = Relay::new(
            Arc::clone(&mempool),
            Arc::clone(&chain),
            network.clone(),
            Arc::clone(&sync),
        );

        let rpc_task = if let Some(addr) = options.rpc {
            let storage_metrics = Arc::new(node::StorageMetrics::new());
            let privacy_metrics = Arc::new(node::PrivacyMetrics::new());
            let ctx = Arc::new(RpcContext::new(
                Arc::clone(&mempool),
                Arc::clone(&chain),
                network.clone(),
                storage_metrics,
                privacy_metrics,
            ));
            let (handle, _) = spawn_rpc_server(Arc::clone(&ctx), addr)
                .await
                .expect("spawn rpc");
            Some(handle)
        } else {
            None
        };

        let peer_task = tokio::spawn(run_peer_event_loop(relay.clone()));
        let chain_task = tokio::spawn(run_chain_event_loop(
            Arc::clone(&chain),
            Arc::clone(&sync),
            network.clone(),
        ));
        let sync_task = tokio::spawn(run_block_sync_task(Arc::clone(&chain), network.clone()));

        Self {
            chain,
            sync,
            _mempool: Arc::clone(&mempool),
            network,
            peer_task,
            chain_task,
            sync_task,
            rpc_task,
        }
    }

    async fn shutdown(self) {
        let TestNode {
            peer_task,
            chain_task,
            sync_task,
            rpc_task,
            ..
        } = self;
        peer_task.abort();
        chain_task.abort();
        sync_task.abort();
        if let Some(handle) = rpc_task {
            handle.abort();
            let _ = handle.await;
        }
        let _ = peer_task.await;
        let _ = chain_task.await;
        let _ = sync_task.await;
    }

    fn apply_block(&self, block: Block) -> [u8; 32] {
        let hash = pow_hash(&block.header);
        {
            let mut guard = self.chain.lock();
            guard.apply_block(block).expect("apply block");
        }
        self.sync.mark_known(hash);
        hash
    }

    fn broadcast_block(&self, hash: [u8; 32]) {
        let item = InventoryItem::block(hash);
        self.network
            .broadcast(NetMessage::Inv(Inventory::single(item)));
    }

    async fn wait_for_height(&self, target: u64) -> bool {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        while Instant::now() < deadline {
            if self.chain.lock().height() >= target {
                return true;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        false
    }

    async fn wait_for_peers(&self, count: usize) -> bool {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        while Instant::now() < deadline {
            if self.network.peer_info().len() >= count {
                return true;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        false
    }

    fn height(&self) -> u64 {
        self.chain.lock().height()
    }

    fn best_hash(&self) -> [u8; 32] {
        self.chain.lock().best_hash()
    }

    fn chain_tip(&self) -> Block {
        self.chain.lock().tip().clone()
    }

    fn network_handle(&self) -> NetworkHandle {
        self.network.clone()
    }
}

fn random_listen() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind temp port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn test_genesis(params: &ChainParams) -> Block {
    let tx = coinbase_tx(GENESIS_TIME);
    let header = BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        merkle_root: merkle_root(std::slice::from_ref(&tx)),
        utxo_root: [0u8; 32],
        time: GENESIS_TIME,
        n_bits: 0x207fffff,
        nonce: 0,
        alg_tag: 1,
    };
    mine_block(header, vec![tx], &params.pow_limit)
}

fn mine_from(prev: &Block, params: &ChainParams, n_bits: u32, time: u64) -> Block {
    let coinbase = coinbase_tx(time);
    let txs = vec![coinbase.clone()];
    let header = BlockHeader {
        version: 1,
        prev_hash: pow_hash(&prev.header),
        merkle_root: merkle_root(&txs),
        utxo_root: [0u8; 32],
        time,
        n_bits,
        nonce: 0,
        alg_tag: 1,
    };
    mine_block(header, txs, &params.pow_limit)
}

fn coinbase_tx(stamp: u64) -> Tx {
    let material = crypto::KeyMaterial::random();
    let scan = material.derive_scan_keypair(0);
    let spend = material.derive_spend_keypair(0);
    let stealth = build_stealth_blob(&scan.public, &spend.public, &stamp.to_le_bytes());
    TxBuilder::new()
        .add_output(Output::new(stealth, 50, OutputMeta::default()))
        .set_witness(Witness {
            range_proofs: Vec::new(),
            stamp,
            extra: Vec::new(),
        })
        .build()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn syncs_headers_and_blocks_between_nodes() {
    let params = ChainParams::default();
    let genesis = test_genesis(&params);
    let data_a = TempDir::new().expect("tempdir");
    let snaps_a = TempDir::new().expect("tempdir");
    let data_b = TempDir::new().expect("tempdir");
    let snaps_b = TempDir::new().expect("tempdir");

    let listen_a = random_listen();
    let listen_b = random_listen();

    let node_a = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(listen_a, Vec::new(), data_a.path(), snaps_a.path(), None),
    )
    .await;
    let node_b = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(
            listen_b,
            vec![listen_a],
            data_b.path(),
            snaps_b.path(),
            None,
        ),
    )
    .await;

    assert!(node_a.wait_for_peers(1).await, "node A failed to see peer");
    assert!(node_b.wait_for_peers(1).await, "node B failed to see peer");

    let block1 = {
        let tip = node_b.chain_tip();
        let time = tip.header.time + params.target_spacing;
        mine_from(&tip, &params, tip.header.n_bits, time)
    };
    let hash1 = node_b.apply_block(block1.clone());
    node_b.broadcast_block(hash1);

    assert!(
        node_a.wait_for_height(1).await,
        "node A failed to sync new block"
    );
    assert_eq!(node_a.height(), 1);
    assert_eq!(node_a.best_hash(), hash1);

    node_a.shutdown().await;
    node_b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reorgs_to_the_longest_chain_across_peers() {
    let params = ChainParams::default();
    let genesis = test_genesis(&params);
    let data_a = TempDir::new().expect("tempdir");
    let snaps_a = TempDir::new().expect("tempdir");
    let data_b = TempDir::new().expect("tempdir");
    let snaps_b = TempDir::new().expect("tempdir");

    let listen_a = random_listen();
    let listen_b = random_listen();

    let node_a = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(listen_a, Vec::new(), data_a.path(), snaps_a.path(), None),
    )
    .await;
    let node_b = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(
            listen_b,
            vec![listen_a],
            data_b.path(),
            snaps_b.path(),
            None,
        ),
    )
    .await;

    assert!(node_a.wait_for_peers(1).await);
    assert!(node_b.wait_for_peers(1).await);

    let block1 = {
        let tip = node_b.chain_tip();
        let time = tip.header.time + params.target_spacing;
        mine_from(&tip, &params, tip.header.n_bits, time)
    };
    let hash1 = node_b.apply_block(block1.clone());
    node_b.broadcast_block(hash1);
    assert!(node_a.wait_for_height(1).await);

    let block2 = {
        let tip = node_b.chain_tip();
        let time = tip.header.time + params.target_spacing;
        mine_from(&tip, &params, tip.header.n_bits, time)
    };
    let hash2 = node_b.apply_block(block2.clone());
    node_b.broadcast_block(hash2);
    assert!(node_a.wait_for_height(2).await);

    // Node A builds an alternative longer chain.
    let alt_time2 = block1.header.time + params.target_spacing + 5;
    let alt_block2 = mine_from(&block1, &params, block2.header.n_bits, alt_time2);
    let alt_hash2 = node_a.apply_block(alt_block2.clone());
    node_a.broadcast_block(alt_hash2);

    let alt_time3 = alt_block2.header.time + params.target_spacing;
    let next_bits = node_a
        .chain
        .lock()
        .next_difficulty_bits()
        .unwrap_or(block2.header.n_bits);
    let alt_block3 = mine_from(&alt_block2, &params, next_bits, alt_time3);
    let alt_hash3 = node_a.apply_block(alt_block3.clone());
    node_a.broadcast_block(alt_hash3);

    assert!(node_b.wait_for_height(3).await, "node B failed to reorg");
    assert_eq!(node_b.height(), 3);
    assert_eq!(node_b.best_hash(), alt_hash3);

    node_a.shutdown().await;
    node_b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persists_chain_across_restart_with_storage_crate() {
    let params = ChainParams::default();
    let genesis = test_genesis(&params);
    let data_dir = TempDir::new().expect("tempdir");
    let snaps_dir = TempDir::new().expect("tempdir");

    let listen_first = random_listen();
    let node_one = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(
            listen_first,
            Vec::new(),
            data_dir.path(),
            snaps_dir.path(),
            None,
        ),
    )
    .await;

    let block = {
        let tip = node_one.chain_tip();
        let time = tip.header.time + params.target_spacing;
        mine_from(&tip, &params, tip.header.n_bits, time)
    };
    let hash = node_one.apply_block(block.clone());
    node_one.broadcast_block(hash);
    assert!(node_one.wait_for_height(1).await);
    node_one.shutdown().await;

    let listen_second = random_listen();
    let node_two = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(
            listen_second,
            Vec::new(),
            data_dir.path(),
            snaps_dir.path(),
            None,
        ),
    )
    .await;
    assert_eq!(node_two.height(), 1, "height should persist after restart");
    assert_eq!(node_two.best_hash(), hash, "best hash should persist");
    node_two.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exposes_metrics_over_http() {
    let params = ChainParams::default();
    let genesis = test_genesis(&params);
    let data_dir = TempDir::new().expect("tempdir");
    let snaps_dir = TempDir::new().expect("tempdir");

    let listen = random_listen();
    let rpc_addr = random_listen();
    let node = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(
            listen,
            Vec::new(),
            data_dir.path(),
            snaps_dir.path(),
            Some(rpc_addr),
        ),
    )
    .await;

    let client = Client::new();
    let url = format!("http://{}/metrics", rpc_addr);
    let mut success = false;
    for _ in 0..50 {
        if let Ok(response) = client.get(&url).send().await
            && let Ok(body) = response.text().await
            && body.contains("pqpriv_tip_height 0")
        {
            success = true;
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert!(success, "failed to fetch initial metrics");

    let block = {
        let tip = node.chain_tip();
        let time = tip.header.time + params.target_spacing;
        mine_from(&tip, &params, tip.header.n_bits, time)
    };
    let hash = node.apply_block(block.clone());
    node.broadcast_block(hash);
    assert!(node.wait_for_height(1).await);

    let mut updated = false;
    for _ in 0..50 {
        if let Ok(response) = client.get(&url).send().await
            && let Ok(body) = response.text().await
            && body.contains("pqpriv_tip_height 1")
        {
            updated = true;
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert!(updated, "metrics endpoint did not reflect new height");
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_peers_with_invalid_handshake() {
    let params = ChainParams::default();
    let genesis = test_genesis(&params);
    let data_dir = TempDir::new().expect("tempdir");
    let snaps_dir = TempDir::new().expect("tempdir");

    let listen_a = random_listen();
    let node_a = TestNode::spawn(
        params.clone(),
        genesis.clone(),
        NodeOptions::new(
            listen_a,
            Vec::new(),
            data_dir.path(),
            snaps_dir.path(),
            None,
        ),
    )
    .await;

    let bad_config = P2pConfig {
        listen: random_listen(),
        seeds: vec![listen_a],
        handshake_key: [0xAA; 32],
        ..Default::default()
    };

    let mut version = Version::user_agent("malicious", 0);
    let advertised = NodeAddr::new(
        bad_config.listen.ip().to_string(),
        bad_config.listen.port(),
        Services::NODE_NETWORK,
    );
    version.receiver = advertised.clone();
    version.sender = advertised;

    let malicious = start_network(bad_config, version)
        .await
        .expect("start misconfigured network");

    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(
        node_a.network_handle().peer_info().is_empty(),
        "malicious peer should not complete the handshake"
    );
    assert!(
        malicious.peer_info().is_empty(),
        "misconfigured node should not establish any peers"
    );

    drop(malicious);
    node_a.shutdown().await;
}
