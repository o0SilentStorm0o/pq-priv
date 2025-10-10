use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

mod cfg;
mod mempool;
mod relay;
mod rpc;
mod state;
mod sync;

use clap::{Parser, Subcommand};
use consensus::{Block, BlockHeader, ChainParams, merkle_root, pow_hash};
use crypto::{self, KeyMaterial};
use pow::mine_block;
use storage::{SnapshotConfig, Store};
use tracing::info;
use tx::{Output, OutputMeta, Tx, TxBuilder, Witness, build_stealth_blob};

use crate::cfg::NodeConfig;
use crate::state::ChainState;

#[derive(Parser)]
#[command(author, version, about = "PQ-PRIV reference node prototype")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a minimal single-node loop and mine a handful of blocks.
    Run {
        #[arg(long, default_value_t = 1)]
        blocks: u32,
    },
    /// Generate a new wallet seed (placeholder mnemonic support).
    Keygen,
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Run { blocks } => run_node(blocks),
        Commands::Keygen => {
            let material = KeyMaterial::random();
            info!(
                "seed" = hex::encode(material.derive_view_token("seed").tag),
                "Generated placeholder seed"
            );
        }
    }
}

fn run_node(blocks: u32) {
    let config = NodeConfig::default();
    let params = ChainParams::default();
    let genesis = genesis_block(&params);
    info!(hash = ?pow_hash(&genesis.header), "Loaded genesis block");
    fs::create_dir_all(&config.db_path).expect("create data dir");
    fs::create_dir_all(&config.snapshots_path).expect("create snapshot dir");
    let store = Store::open(&config.db_path).expect("open storage");
    let mut chain_state =
        ChainState::bootstrap(params.clone(), store, genesis.clone()).expect("bootstrap chain");
    chain_state
        .configure_snapshots(SnapshotConfig::new(
            config.snapshots_path.clone(),
            config.snapshot_interval,
            config.snapshot_keep,
        ))
        .expect("configure snapshots");
    for height in 1..=blocks {
        let prev = chain_state.tip().clone();
        let n_bits = chain_state
            .next_difficulty_bits()
            .unwrap_or(prev.header.n_bits);
        let mut header = block_template(&prev, n_bits);
        let txs = vec![coinbase_tx(height as u64)];
        header.merkle_root = merkle_root(&txs);
        let block = mine_block(header, txs, &params.pow_limit);
        chain_state.apply_block(block.clone()).expect("apply block");
        info!(
            height,
            hash = ?pow_hash(&block.header),
            nonce = block.header.nonce,
            utxos = chain_state.utxo_count().unwrap_or_default(),
            "Mined block"
        );
    }
}

fn block_template(prev: &Block, n_bits: u32) -> BlockHeader {
    let prev_hash = pow_hash(&prev.header);
    let mut time = current_time();
    if time <= prev.header.time {
        time = prev.header.time + 1;
    }
    BlockHeader {
        version: 1,
        prev_hash,
        merkle_root: [0u8; 32],
        utxo_root: [0u8; 32],
        time,
        n_bits,
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

fn genesis_block(params: &ChainParams) -> Block {
    let tx = coinbase_tx(0);
    let header = BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        merkle_root: merkle_root(std::slice::from_ref(&tx)),
        utxo_root: [0u8; 32],
        time: current_time(),
        n_bits: 0x207fffff,
        nonce: 0,
        alg_tag: 1,
    };
    mine_block(header, vec![tx], &params.pow_limit)
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
