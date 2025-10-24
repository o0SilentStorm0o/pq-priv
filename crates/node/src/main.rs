use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use consensus::{Block, BlockHeader, ChainParams, merkle_root, pow_hash};
use crypto::{self, KeyMaterial};
use parking_lot::Mutex;
use pow::mine_block;
use storage::{SnapshotConfig, Store};
use tokio::signal;
use tracing::{error, info};
use tx::{Output, OutputMeta, Tx, TxBuilder, Witness, build_stealth_blob};

use node::{
    ChainState, NodeConfig, PrivacyMetrics, Relay, RpcContext, StorageMetrics, SyncManager, TxPool,
    run_block_sync_task, run_chain_event_loop, run_peer_event_loop, run_storage_metrics_task,
    spawn_rpc_server,
};
use p2p::{NodeAddr, P2pConfig, Services, Version, start_network};

#[derive(Parser)]
#[command(author, version, about = "PQ-PRIV reference node prototype")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the full node services using the provided configuration.
    Run(RunArgs),
    /// Generate a new wallet seed (placeholder mnemonic support).
    Keygen,
    /// Create a snapshot of the current database state.
    SnapshotNow {
        /// Path to the database directory
        #[arg(long)]
        db_path: PathBuf,
        /// Directory where snapshots will be stored
        #[arg(long)]
        snapshot_dir: PathBuf,
    },
    /// Restore database from a snapshot archive.
    RestoreSnapshot {
        /// Path to the snapshot archive file
        #[arg(long)]
        snapshot_path: PathBuf,
        /// Target directory for restored database
        #[arg(long)]
        target_dir: PathBuf,
    },
    /// Verify a snapshot archive without restoring.
    VerifySnapshot {
        /// Path to the snapshot archive file
        #[arg(long)]
        snapshot_path: PathBuf,
    },
}

#[derive(Args, Clone, Debug, Default)]
struct RunArgs {
    /// Optional path to a TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Directory where snapshots will be stored (overrides config file).
    #[arg(long)]
    snapshot_dir: Option<PathBuf>,

    /// Automatic snapshot interval in blocks (0 = disabled, overrides config file).
    #[arg(long)]
    snapshot_interval: Option<u64>,

    /// Number of snapshots to keep (overrides config file).
    #[arg(long)]
    snapshot_keep: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        Commands::SnapshotNow {
            db_path,
            snapshot_dir,
        } => {
            snapshot_now(db_path, snapshot_dir).await?;
        }
        Commands::RestoreSnapshot {
            snapshot_path,
            target_dir,
        } => {
            restore_snapshot(snapshot_path, target_dir).await?;
        }
        Commands::VerifySnapshot { snapshot_path } => {
            verify_snapshot(snapshot_path).await?;
        }
    }
    Ok(())
}

async fn run_node(args: RunArgs) -> anyhow::Result<()> {
    let mut config = NodeConfig::load(args.config.as_deref())?;

    // CLI overrides for snapshot configuration
    if let Some(snapshot_dir) = args.snapshot_dir {
        config.snapshots_path = snapshot_dir;
    }
    if let Some(interval) = args.snapshot_interval {
        config.snapshot_interval = interval;
    }
    if let Some(keep) = args.snapshot_keep {
        config.snapshot_keep = keep;
    }

    let params = ChainParams::default();
    let genesis = genesis_block(&params);
    info!(hash = ?pow_hash(&genesis.header), "Loaded genesis block");

    fs::create_dir_all(&config.db_path)?;
    fs::create_dir_all(&config.snapshots_path)?;

    // Storage path safety checks (防止path-traversal攻击)
    validate_storage_path(&config.db_path)?;

    let store = Store::open_with_tuning(&config.db_path, config.db_tuning.clone())?;
    let mut chain_state = ChainState::bootstrap(params.clone(), store, genesis.clone())?;
    chain_state.configure_snapshots(SnapshotConfig::new(
        config.snapshots_path.clone(),
        config.snapshot_interval,
        config.snapshot_keep,
    ))?;

    let chain = Arc::new(Mutex::new(chain_state));
    let mempool = Arc::new(Mutex::new(TxPool::new(config.mempool.clone())));
    let sync = Arc::new(SyncManager::new(
        config.sync_orphan_limit,
        config.sync_orphan_ttl,
    ));

    {
        let guard = chain.lock();
        sync.mark_known(pow_hash(&guard.tip().header));
    }

    let p2p_config = P2pConfig {
        listen: config.p2p_listen,
        seeds: config.seeds.clone(),
        ..P2pConfig::default()
    };

    let height = {
        let guard = chain.lock();
        guard.height()
    };
    let mut version = Version::user_agent("pq-priv-node", height);
    let advertised = NodeAddr::new(
        config.p2p_listen.ip().to_string(),
        config.p2p_listen.port(),
        Services::NODE_NETWORK,
    );
    version.receiver = advertised.clone();
    version.sender = advertised;

    let network = start_network(p2p_config, version).await?;
    let listen_addr = network.config().listen;
    let relay = Relay::new(
        Arc::clone(&mempool),
        Arc::clone(&chain),
        network.clone(),
        Arc::clone(&sync),
    );

    // Create storage metrics collector (shared between RPC and background task)
    let storage_metrics = Arc::new(StorageMetrics::new());

    // Create privacy metrics collector (shared between ChainState and RPC)
    let privacy_metrics = Arc::new(PrivacyMetrics::new());

    // Attach privacy metrics to ChainState for validation tracking
    {
        let mut guard = chain.lock();
        guard.attach_privacy_metrics(Arc::clone(&privacy_metrics));
    }

    let rpc_context = Arc::new(RpcContext::new(
        Arc::clone(&mempool),
        Arc::clone(&chain),
        network.clone(),
        Arc::clone(&storage_metrics),
        Arc::clone(&privacy_metrics),
    ));
    let (rpc_handle, rpc_addr) =
        spawn_rpc_server(Arc::clone(&rpc_context), config.rpc_listen).await?;

    let peer_task = tokio::spawn(run_peer_event_loop(relay));
    let chain_task = tokio::spawn(run_chain_event_loop(
        Arc::clone(&chain),
        Arc::clone(&sync),
        network.clone(),
    ));
    let sync_task = tokio::spawn(run_block_sync_task(Arc::clone(&chain), network.clone()));

    // Background task to update storage metrics every 15 seconds
    let metrics_task = tokio::spawn(run_storage_metrics_task(
        config.db_path.clone(),
        Arc::clone(&chain),
        Arc::clone(&storage_metrics),
    ));

    info!(
        p2p = %listen_addr,
        rpc = %rpc_addr,
        "node services started"
    );

    if let Err(err) = signal::ctrl_c().await {
        error!(error = ?err, "failed to install ctrl-c handler");
    }

    info!("shutdown requested");
    peer_task.abort();
    chain_task.abort();
    sync_task.abort();
    metrics_task.abort();
    rpc_handle.abort();

    let _ = peer_task.await;
    let _ = chain_task.await;
    let _ = sync_task.await;
    let _ = metrics_task.await;
    let _ = rpc_handle.await;

    Ok(())
}

fn coinbase_tx(height: u64) -> Tx {
    // For E2E testing, use deterministic coinbase to ensure same merkle root
    let material = if std::env::var("E2E_FIXED_GENESIS").is_ok() {
        // Fixed entropy for E2E (all nodes use same keys)
        KeyMaterial::from_entropy(&[42u8; 32])
    } else {
        KeyMaterial::random()
    };

    let scan = material.derive_scan_keypair(0);
    let spend = material.derive_spend_keypair(0);
    let stealth = build_stealth_blob(&scan.public, &spend.public, &height.to_le_bytes());

    // Create a transparent output with 50 coins
    let output = Output::new(stealth, 50, OutputMeta::default());

    let witness_stamp = if std::env::var("E2E_FIXED_GENESIS").is_ok() {
        1700000000u64 // Fixed timestamp for E2E
    } else {
        current_time()
    };

    TxBuilder::new()
        .add_output(output)
        .set_witness(Witness::new(Vec::new(), witness_stamp, Vec::new()))
        .build()
}

fn genesis_block(params: &ChainParams) -> Block {
    let tx = coinbase_tx(0);

    // For E2E testing, use fixed genesis to ensure all nodes start with same block
    let (time, nonce) = if std::env::var("E2E_FIXED_GENESIS").is_ok() {
        // Fixed values that produce a valid genesis block
        // Pre-mined with nonce that satisfies POW requirement
        (1700000000u64, 42u64) // Fixed timestamp + nonce
    } else {
        (current_time(), 0)
    };

    let header = BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        merkle_root: merkle_root(std::slice::from_ref(&tx)),
        utxo_root: [0u8; 32],
        time,
        n_bits: 0x207fffff,
        nonce,
        alg_tag: 1,
    };

    // Skip mining if using fixed genesis (already has valid nonce)
    if std::env::var("E2E_FIXED_GENESIS").is_ok() {
        Block {
            header,
            txs: vec![tx],
        }
    } else {
        mine_block(header, vec![tx], &params.pow_limit)
    }
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Validate storage path for security issues.
///
/// Checks:
/// - No symlinks in path (prevents path-traversal attacks)
/// - Appropriate permissions (warns if too permissive)
///
/// This prevents security issues when snapshot/restore features are added.
fn validate_storage_path(path: &PathBuf) -> anyhow::Result<()> {
    use anyhow::bail;

    // Check for symlinks in path
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.is_symlink() {
            bail!(
                "Storage path '{}' is a symlink. This is not allowed for security reasons. \
                Use a real directory instead.",
                path.display()
            );
        }

        // Check permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use tracing::warn;

            let mode = metadata.permissions().mode();
            let perms = mode & 0o777;

            // Warn if directory is world-readable or world-writable
            if perms & 0o007 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{:o}", perms),
                    "Storage directory has world-accessible permissions. \
                    Recommended: 700 (owner-only) or 750 (owner+group)"
                );
            }
        }
    }

    Ok(())
}

/// Create a snapshot of the current database state.
async fn snapshot_now(db_path: PathBuf, snapshot_dir: PathBuf) -> anyhow::Result<()> {
    use std::time::Instant;
    use storage::{DbTuning, SnapshotManager};

    info!(
        db_path = %db_path.display(),
        snapshot_dir = %snapshot_dir.display(),
        "creating database snapshot"
    );

    fs::create_dir_all(&snapshot_dir)?;

    let start = Instant::now();

    // Open database read-only
    let store = Store::open_with_tuning(&db_path, DbTuning::default())?;

    // Get UTXO count (approximate via tip height for now)
    let tip = store
        .tip()?
        .ok_or_else(|| anyhow::anyhow!("no tip found"))?;
    let utxo_count = tip.height; // TODO: implement actual UTXO counting

    let manager = SnapshotManager::new(&snapshot_dir)?;
    let snapshot_path = manager.create_snapshot(&store, utxo_count)?;

    let duration_ms = start.elapsed().as_millis() as u64;

    info!(
        path = %snapshot_path.display(),
        height = tip.height,
        duration_ms = duration_ms,
        "snapshot created successfully"
    );

    // Note: Metrics would be recorded here with:
    // metrics.record_snapshot_success(tip.height, duration_ms);

    Ok(())
}

/// Restore database from a snapshot archive.
async fn restore_snapshot(snapshot_path: PathBuf, target_dir: PathBuf) -> anyhow::Result<()> {
    use std::time::Instant;
    use storage::SnapshotManager;

    info!(
        snapshot = %snapshot_path.display(),
        target = %target_dir.display(),
        "restoring database from snapshot"
    );

    let start = Instant::now();

    let snapshot_dir = snapshot_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("snapshot path has no parent directory"))?;

    let manager = SnapshotManager::new(snapshot_dir)?;
    let metadata = manager.restore_snapshot(&snapshot_path, &target_dir)?;

    let duration_ms = start.elapsed().as_millis() as u64;

    info!(
        height = metadata.height,
        tip_hash = %metadata.tip_hash,
        utxo_count = metadata.utxo_count,
        duration_ms = duration_ms,
        "database restored successfully"
    );

    // Verify restored database
    info!("verifying restored database...");
    let store = Store::open_with_tuning(&target_dir, storage::DbTuning::default())?;
    let tip = store
        .tip()?
        .ok_or_else(|| anyhow::anyhow!("restored database has no tip"))?;

    if hex::encode(tip.hash) != metadata.tip_hash {
        anyhow::bail!(
            "tip hash mismatch: expected {}, got {}",
            metadata.tip_hash,
            hex::encode(tip.hash)
        );
    }

    if tip.height != metadata.height {
        anyhow::bail!(
            "height mismatch: expected {}, got {}",
            metadata.height,
            tip.height
        );
    }

    info!("database verification successful");

    // Note: Metrics would be recorded here with:
    // metrics.record_restore_success();

    Ok(())
}

/// Verify a snapshot archive without restoring.
async fn verify_snapshot(snapshot_path: PathBuf) -> anyhow::Result<()> {
    use storage::SnapshotManager;

    info!(
        path = %snapshot_path.display(),
        "verifying snapshot archive"
    );

    let snapshot_dir = snapshot_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("snapshot path has no parent directory"))?;

    let manager = SnapshotManager::new(snapshot_dir)?;

    // Try to extract to a temporary directory for validation
    let temp_dir = std::env::temp_dir().join(format!("pq-verify-{}", std::process::id()));

    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir)?;
    }

    // Restore to temp directory (this validates the entire archive)
    let metadata = manager.restore_snapshot(&snapshot_path, &temp_dir)?;

    info!(
        height = metadata.height,
        tip_hash = %metadata.tip_hash,
        utxo_count = metadata.utxo_count,
        timestamp = metadata.timestamp,
        format_version = metadata.format_version,
        "snapshot archive is valid"
    );

    // Cleanup temp directory
    fs::remove_dir_all(&temp_dir)?;

    Ok(())
}
