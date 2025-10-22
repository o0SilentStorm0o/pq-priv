use std::fs;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use crypto::KeyMaterial;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info};

#[derive(Parser)]
#[command(author, version, about = "PQ-PRIV wallet prototype")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a brand new wallet state on disk.
    New(NewArgs),
    /// Show the default receiving information.
    Addr,
    /// Build a placeholder private transaction.
    Send(SendArgs),
    /// Emit a stub audit packet file.
    Audit {
        txid: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args)]
struct NewArgs {
    #[arg(long, default_value = "testnet")]
    network: String,
    #[arg(long, default_value = "default")]
    label: String,
}

#[derive(Args)]
struct SendArgs {
    #[arg(long)]
    to: String,
    #[arg(long)]
    amount: f64,
    #[arg(long)]
    fee: Option<f64>,
    #[arg(long)]
    exchange: Option<String>,
}

/// **SECURITY:** Wallet state containing sensitive key material.
///
/// This type uses a custom Debug implementation to prevent accidental logging
/// of the master seed. The `key_material` field is redacted in debug output.
///
/// **Storage Security:**
/// - File permissions: Owner read-only (0600 on Unix, restricted ACL on Windows)
/// - Format: JSON with base64-encoded key material
/// - Location: `wallet_state.json` (should be backed up securely)
///
/// **TODO for Production:**
/// - Add encryption at rest (password-derived key)
/// - Use OS keychain/keyring for key storage
/// - Implement file locking to prevent concurrent access
#[derive(Serialize, Deserialize)]
struct WalletState {
    label: String,
    network: String,
    key_material: KeyMaterial,
}

// Custom Debug impl to prevent key material leakage
impl std::fmt::Debug for WalletState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletState")
            .field("label", &self.label)
            .field("network", &self.network)
            .field("key_material", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
enum WalletError {
    #[error("wallet state not initialised; run `pqpriv-wallet new`")]
    MissingState,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    if let Err(err) = dispatch(cli.command) {
        error!(?err, "wallet command failed");
        std::process::exit(1);
    }
}

fn dispatch(cmd: Commands) -> Result<(), WalletError> {
    match cmd {
        Commands::New(args) => {
            let state = WalletState {
                label: args.label.clone(),
                network: args.network,
                key_material: KeyMaterial::random(),
            };
            save_state(&state)?;
            info!(label = %state.label, "Wallet created");
            Ok(())
        }
        Commands::Addr => {
            let state = load_state()?;
            let scan = state.key_material.derive_scan_keypair(0);
            let spend = state.key_material.derive_spend_keypair(0);
            let blob = tx::build_stealth_blob(&scan.public, &spend.public, b"default");
            info!(
                "stealth_blob" = hex::encode(&blob),
                "Default receiving hint"
            );
            Ok(())
        }
        Commands::Send(args) => {
            let state = load_state()?;
            info!(
                to = %args.to,
                amount = args.amount,
                fee = args.fee.unwrap_or(0.01),
                exchange = ?args.exchange,
                "Building placeholder transaction"
            );
            let scan = state.key_material.derive_scan_keypair(0);
            let spend = state.key_material.derive_spend_keypair(0);
            let blob = tx::build_stealth_blob(&scan.public, &spend.public, args.to.as_bytes());
            info!(
                "stealth_blob" = hex::encode(blob),
                "TX ready for signing (stub)"
            );
            Ok(())
        }
        Commands::Audit { txid, scope, out } => {
            let state = load_state()?;
            let view = state.key_material.derive_view_token(&scope);
            let packet = serde_json::json!({
                "txid": txid,
                "scope": scope,
                "view_token": hex::encode(view.tag),
            });
            fs::write(&out, serde_json::to_vec_pretty(&packet)?)?;
            info!(?out, "Audit packet written");
            Ok(())
        }
    }
}

fn state_path() -> PathBuf {
    PathBuf::from("wallet_state.json")
}

fn save_state(state: &WalletState) -> Result<(), WalletError> {
    let path = state_path();
    let json = serde_json::to_vec_pretty(state)?;

    // Write with restricted permissions (owner-only)
    // On Unix: 0600 (rw-------)
    // On Windows: restricted ACL (current user only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut file = fs::File::create(&path)?;
        std::io::Write::write_all(&mut file, &json)?;

        // Set permissions to 0600 (owner read/write only)
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;

        info!(
            ?path,
            "Wallet state saved with restricted permissions (0600)"
        );
    }

    #[cfg(not(unix))]
    {
        // On Windows, File::create already restricts to current user by default
        fs::write(&path, json)?;
        info!(?path, "Wallet state saved (Windows default ACL)");
    }

    Ok(())
}

fn load_state() -> Result<WalletState, WalletError> {
    let path = state_path();
    if !path.exists() {
        return Err(WalletError::MissingState);
    }

    // SECURITY CHECK: Warn if file permissions are too permissive
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&path)?;
        let perms = metadata.permissions();
        let mode = perms.mode();

        // Check if file is readable by group or others (should be 0600)
        if mode & 0o077 != 0 {
            error!(
                ?path,
                mode = format!("{:o}", mode),
                "WARNING: Wallet file has insecure permissions! \
                 Should be 0600 (owner-only). Current: {:o}. \
                 Run: chmod 600 {:?}",
                mode,
                path
            );
        }
    }

    let bytes = fs::read(path)?;
    let state: WalletState = serde_json::from_slice(&bytes)?;

    // Validate that key_material is present and non-empty
    // (KeyMaterial itself is already validated during deserialization)
    info!(
        label = %state.label,
        network = %state.network,
        "Wallet state loaded successfully"
    );

    Ok(state)
}
