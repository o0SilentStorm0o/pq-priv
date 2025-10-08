use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use consensus::{Block, BlockHeader, ChainParams, pow_hash};
use crypto::{self, KeyMaterial};
use pow::mine_block;
use tracing::info;
use tx::{Output, OutputMeta, Tx, TxBuilder, Witness, build_stealth_blob};
use utxo::{MemoryUtxoStore, apply_block};

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
    let _params = ChainParams::default();
    let genesis = genesis_block();
    info!(hash = ?pow_hash(&genesis.header), "Loaded genesis block");
    let mut chain = vec![genesis.clone()];
    let mut utxo = MemoryUtxoStore::new();
    apply_block(&mut utxo, &genesis, 0).expect("apply genesis");
    for height in 1..=blocks {
        let prev = chain.last().unwrap();
        let mut header = block_template(prev);
        let txs = vec![coinbase_tx(height as u64)];
        header.merkle_root = compute_merkle_root(&txs);
        let block = mine_block(header, txs);
        apply_block(&mut utxo, &block, height as u64).expect("apply block");
        info!(
            height,
            hash = ?pow_hash(&block.header),
            nonce = block.header.nonce,
            utxos = utxo.utxo_count(),
            "Mined block"
        );
        chain.push(block);
    }
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
        merkle_root: compute_merkle_root(std::slice::from_ref(&tx)),
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
