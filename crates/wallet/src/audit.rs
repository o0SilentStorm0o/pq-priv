//! Audit packet generation for exchange compliance (Sprint 9 §10).
//!
//! This module implements the three-tier audit framework from the whitepaper:
//! - **L1 (Existence)**: Proves spend tag is valid without revealing amount/sender
//! - **L2 (Amount)**: Additionally reveals transaction amount
//! - **L3 (Full)**: Additionally reveals sender identity
//!
//! **Security Model:**
//! - Packets are encrypted with exchange's public key (Kyber512 + X25519 hybrid)
//! - Signatures use Dilithium2 (post-quantum secure)
//! - Key rotation supported via JWKS-like structure

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Audit disclosure levels (§10.2 Compliance Tiers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditLevel {
    /// L1: Existence only (spend tag + nullifier).
    /// Proves: "This transaction is valid and not double-spent"
    /// Reveals: Nothing about amount or identity
    L1Existence,

    /// L2: L1 + transaction amount.
    /// Proves: "This transaction spent X amount"
    /// Reveals: Amount (but not sender/receiver identity)
    L2Amount,

    /// L3: L2 + sender identity.
    /// Proves: "Person X sent Y amount"
    /// Reveals: Full transaction details (for regulatory compliance)
    L3Full,
}

/// Audit packet metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditMetadata {
    /// Audit level (L1/L2/L3).
    pub level: AuditLevel,

    /// Transaction ID being audited.
    pub txid: String,

    /// Timestamp of audit packet creation (Unix seconds).
    pub timestamp: u64,

    /// Wallet version that created this packet.
    pub wallet_version: String,

    /// Exchange public key ID (for key rotation).
    pub exchange_key_id: Option<String>,
}

/// L1 audit data: Existence proof only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L1Data {
    /// Spend tag (links to exchange's database).
    pub spend_tag: [u8; 32],

    /// Nullifier (proves no double-spend).
    pub nullifier: [u8; 32],

    /// STARK proof (proves validity).
    #[serde(with = "serde_bytes")]
    pub stark_proof: Vec<u8>,
}

/// L2 audit data: L1 + amount disclosure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L2Data {
    /// L1 data (spend tag, nullifier, proof).
    pub l1: L1Data,

    /// Transaction amount (in satoshis or smallest unit).
    pub amount: u64,

    /// Range proof opening (proves amount matches commitment).
    #[serde(with = "serde_bytes")]
    pub range_proof_opening: Vec<u8>,
}

/// L3 audit data: L2 + identity disclosure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L3Data {
    /// L2 data (L1 + amount).
    pub l2: L2Data,

    /// Sender's public spend key (for identity verification).
    pub sender_spend_pubkey: [u8; 32],

    /// Sender's public view key.
    pub sender_view_pubkey: [u8; 32],

    /// Optional: KYC document hash (if available).
    pub kyc_hash: Option<[u8; 32]>,
}

/// Encrypted audit packet (ready for exchange submission).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditPacket {
    /// Packet metadata (plaintext).
    pub metadata: AuditMetadata,

    /// Encrypted payload (Kyber512 + X25519 hybrid encryption).
    /// Contains: L1Data | L2Data | L3Data (depending on level)
    #[serde(with = "serde_bytes")]
    pub encrypted_payload: Vec<u8>,

    /// Dilithium2 signature over (metadata || encrypted_payload).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("missing spend tag")]
    MissingSpendTag,

    #[error("missing nullifier")]
    MissingNullifier,

    #[error("encryption not yet implemented")]
    EncryptionNotImplemented,

    #[error("signing not yet implemented")]
    SigningNotImplemented,
}

/// Create an audit packet for exchange compliance.
///
/// **Current Status**: Placeholder implementation that serializes audit data
/// but uses stub encryption/signing. Real Kyber512+X25519 and Dilithium2
/// will be wired up in Step 6 (post-quantum crypto integration).
///
/// # Arguments
///
/// * `level` - Audit disclosure level (L1/L2/L3)
/// * `txid` - Transaction ID being audited
/// * `spend_tag` - Spend tag from TX witness
/// * `nullifier` - Nullifier from TX witness
/// * `stark_proof` - STARK proof bytes (from prover)
/// * `amount` - Transaction amount (required for L2/L3)
/// * `sender_keys` - Sender identity keys (required for L3)
/// * `exchange_pubkey` - Exchange's public encryption key (for packet encryption)
///
/// # Returns
///
/// * `Ok(AuditPacket)` - Encrypted packet ready for submission
/// * `Err(AuditError)` - If required fields are missing
#[allow(clippy::too_many_arguments)]
pub fn create_audit_packet(
    level: AuditLevel,
    txid: String,
    spend_tag: [u8; 32],
    nullifier: [u8; 32],
    stark_proof: Vec<u8>,
    amount: Option<u64>,
    sender_keys: Option<([u8; 32], [u8; 32])>,
    _exchange_pubkey: Option<&[u8]>,
) -> Result<AuditPacket, AuditError> {
    // Build audit data based on level
    let plaintext_data = match level {
        AuditLevel::L1Existence => {
            let l1 = L1Data {
                spend_tag,
                nullifier,
                stark_proof,
            };
            serde_json::to_vec(&l1).unwrap()
        }
        AuditLevel::L2Amount => {
            let amount = amount.ok_or(AuditError::MissingSpendTag)?;
            let l1 = L1Data {
                spend_tag,
                nullifier,
                stark_proof: stark_proof.clone(),
            };
            let l2 = L2Data {
                l1,
                amount,
                range_proof_opening: Vec::new(), // TODO: Extract from range proof
            };
            serde_json::to_vec(&l2).unwrap()
        }
        AuditLevel::L3Full => {
            let amount = amount.ok_or(AuditError::MissingSpendTag)?;
            let (spend_pk, view_pk) = sender_keys.ok_or(AuditError::MissingNullifier)?;
            let l1 = L1Data {
                spend_tag,
                nullifier,
                stark_proof: stark_proof.clone(),
            };
            let l2 = L2Data {
                l1,
                amount,
                range_proof_opening: Vec::new(),
            };
            let l3 = L3Data {
                l2,
                sender_spend_pubkey: spend_pk,
                sender_view_pubkey: view_pk,
                kyc_hash: None,
            };
            serde_json::to_vec(&l3).unwrap()
        }
    };

    let metadata = AuditMetadata {
        level,
        txid,
        timestamp: current_timestamp(),
        wallet_version: env!("CARGO_PKG_VERSION").to_string(),
        exchange_key_id: None, // TODO: Key rotation support
    };

    // Placeholder encryption (TODO: Kyber512 + X25519 hybrid in Step 6)
    // Real implementation would:
    // 1. Generate ephemeral Kyber512 keypair
    // 2. Encapsulate to exchange's Kyber public key → shared_secret_kyber
    // 3. Generate ephemeral X25519 keypair
    // 4. ECDH with exchange's X25519 public key → shared_secret_x25519
    // 5. KDF(shared_secret_kyber || shared_secret_x25519) → aes_key
    // 6. AES-256-GCM encrypt plaintext_data with aes_key
    let encrypted_payload = plaintext_data; // Stub: Just copy plaintext

    // Placeholder signature (TODO: Dilithium2 in Step 6)
    // Real implementation would:
    // 1. Serialize (metadata || encrypted_payload)
    // 2. Sign with wallet's Dilithium2 private key
    // 3. Append signature for verification
    let signature = vec![0u8; 64]; // Stub signature

    Ok(AuditPacket {
        metadata,
        encrypted_payload,
        signature,
    })
}

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l1_audit_packet() {
        let packet = create_audit_packet(
            AuditLevel::L1Existence,
            "abc123".to_string(),
            [1u8; 32],
            [2u8; 32],
            vec![0; 100], // Stub proof
            None,
            None,
            None,
        )
        .expect("L1 packet");

        assert_eq!(packet.metadata.level, AuditLevel::L1Existence);
        assert_eq!(packet.metadata.txid, "abc123");
        assert!(!packet.encrypted_payload.is_empty());
    }

    #[test]
    fn test_l2_audit_packet() {
        let packet = create_audit_packet(
            AuditLevel::L2Amount,
            "def456".to_string(),
            [1u8; 32],
            [2u8; 32],
            vec![0; 100],
            Some(50000), // 50k sats
            None,
            None,
        )
        .expect("L2 packet");

        assert_eq!(packet.metadata.level, AuditLevel::L2Amount);
    }

    #[test]
    fn test_l3_audit_packet() {
        let packet = create_audit_packet(
            AuditLevel::L3Full,
            "ghi789".to_string(),
            [1u8; 32],
            [2u8; 32],
            vec![0; 100],
            Some(100000),
            Some(([10u8; 32], [20u8; 32])),
            None,
        )
        .expect("L3 packet");

        assert_eq!(packet.metadata.level, AuditLevel::L3Full);
    }

    #[test]
    fn test_l2_requires_amount() {
        let result = create_audit_packet(
            AuditLevel::L2Amount,
            "fail".to_string(),
            [1u8; 32],
            [2u8; 32],
            vec![0; 100],
            None, // Missing amount
            None,
            None,
        );

        assert!(result.is_err());
    }
}
