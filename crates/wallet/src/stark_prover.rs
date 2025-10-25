//! STARK prover module for generating privacy proofs.
//!
//! Integrates with crypto-stark crate for real STARK proving.

use crypto_stark::params::{HashFunction, SecurityLevel as CryptoSecurityLevel};
use crypto_stark::{prove_one_of_many, StarkParams, StarkWitness as CryptoWitness, GOLDILOCKS_PRIME};
use thiserror::Error;
use tx::{compute_nullifier, compute_spend_tag, Nullifier, SpendTag};

/// Error types for STARK proof generation.
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("anonymity set too small: {0} (minimum: 32)")]
    AnonymitySetTooSmall(usize),

    #[error("anonymity set too large: {0} (maximum: 256)")]
    AnonymitySetTooLarge(usize),

    #[error("invalid commitment")]
    InvalidCommitment,

    #[error("STARK proving failed: {0}")]
    ProvingFailed(String),
}

/// Configuration for STARK proof generation.
#[derive(Clone, Debug)]
pub struct ProverConfig {
    /// Anonymity set size (must be power of 2, range: 32-256).
    pub anonymity_set_size: usize,

    /// Security level: Fast (20 queries), Standard (27), High (40).
    pub security_level: SecurityLevel,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            anonymity_set_size: 64,
            security_level: SecurityLevel::Standard,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SecurityLevel {
    Fast,     // ~80-bit security, 20 FRI queries
    Standard, // ~100-bit security, 27 FRI queries
    High,     // ~128-bit security, 40 FRI queries
}

/// Witness data for STARK proof (private inputs).
#[derive(Clone)]
pub struct StarkWitness {
    /// Spend secret key (never revealed in proof).
    pub sk_spend: [u8; 32],

    /// View secret key (for spend tags).
    pub sk_view: [u8; 32],

    /// Commitment to spend (part of UTXO set).
    pub commitment: [u8; 32],

    /// Network ID (prevents replay across chains).
    pub network_id: u8,

    /// Transaction version (for domain separation).
    pub tx_version: u16,

    /// Epoch number (for spend tag freshness).
    pub epoch: u64,
}

/// Public inputs for STARK proof (visible on-chain).
#[derive(Clone, Debug)]
pub struct PublicInputs {
    /// Nullifier (proves spend without revealing which UTXO).
    pub nullifier: Nullifier,

    /// Spend tag (enables exchange auditing).
    pub spend_tag: SpendTag,

    /// Merkle root of anonymity set.
    pub merkle_root: [u8; 32],
}

/// Placeholder STARK proof structure.
///
/// **TODO**: Replace with actual proof bytes once STARK implementation is complete.
#[derive(Clone, Debug)]
pub struct StarkProof {
    /// Proof bytes (placeholder: empty vec).
    pub proof_bytes: Vec<u8>,

    /// Public inputs.
    pub public_inputs: PublicInputs,

    /// Proof metadata.
    pub metadata: ProofMetadata,
}

#[derive(Clone, Debug)]
pub struct ProofMetadata {
    pub anonymity_set_size: usize,
    pub security_level: String,
    pub proof_size_bytes: usize,
}

/// Generate a STARK proof for a private spend transaction.
///
/// # Arguments
///
/// * `witness` - Private inputs (secret keys, commitment, etc.)
/// * `anonymity_set` - Commitments in the anonymity set (must include witness.commitment)
/// * `config` - Prover configuration (anonymity set size, security level)
///
/// # Returns
///
/// * `Ok(StarkProof)` - Proof with nullifier, spend tag, and STARK proof bytes
/// * `Err(ProverError)` - If validation fails or proving fails
///
/// # Security Notes
///
/// - Nullifier prevents double-spending (derived from sk_spend + commitment)
/// - Spend tag enables exchange compliance (derived from sk_view + commitment + epoch)
/// - STARK proof demonstrates commitment exists in anonymity set
pub fn generate_proof(
    witness: StarkWitness,
    anonymity_set: &[[u8; 32]],
    config: ProverConfig,
) -> Result<StarkProof, ProverError> {
    // Validate anonymity set size
    if anonymity_set.len() < 32 {
        return Err(ProverError::AnonymitySetTooSmall(anonymity_set.len()));
    }
    if anonymity_set.len() > 256 {
        return Err(ProverError::AnonymitySetTooLarge(anonymity_set.len()));
    }
    if !anonymity_set.len().is_power_of_two() {
        return Err(ProverError::AnonymitySetTooSmall(anonymity_set.len()));
    }

    // Verify witness commitment is in anonymity set
    let witness_index = anonymity_set
        .iter()
        .position(|c| c == &witness.commitment)
        .ok_or(ProverError::InvalidCommitment)?;

    // Compute nullifier and spend tag using real Poseidon2
    let nullifier = compute_nullifier(
        &witness.sk_spend,
        &witness.commitment,
        witness.network_id,
        witness.tx_version,
    );

    let spend_tag = compute_spend_tag(&witness.sk_view, &witness.commitment, witness.epoch);

    // Setup STARK parameters
    let security_level = match config.security_level {
        SecurityLevel::Fast => CryptoSecurityLevel::Fast,
        SecurityLevel::Standard => CryptoSecurityLevel::Standard,
        SecurityLevel::High => CryptoSecurityLevel::High,
    };

    let stark_params = StarkParams {
        security: security_level,
        anonymity_set_size: anonymity_set.len(),
        field_modulus: GOLDILOCKS_PRIME,
        hash_function: HashFunction::Poseidon2,
    };

    // Create crypto-stark witness
    let crypto_witness = CryptoWitness {
        index: witness_index,
        commitment: witness.commitment,
        nullifier: nullifier.0,
        tx_version: witness.tx_version,
        network_id: witness.network_id,
        spend_tag: spend_tag.0,
    };

    // Generate STARK proof
    let stark_proof = prove_one_of_many(&stark_params, anonymity_set, &crypto_witness)
        .map_err(|e| ProverError::ProvingFailed(e.to_string()))?;

    // Compute Merkle root from proof (now 32 bytes)
    let merkle_root = stark_proof.trace_commitment;

    let public_inputs = PublicInputs {
        nullifier,
        spend_tag,
        merkle_root,
    };

    let security_str = match config.security_level {
        SecurityLevel::Fast => "fast",
        SecurityLevel::Standard => "standard",
        SecurityLevel::High => "high",
    };

    // Serialize proof (simplified - just store trace commitment for now)
    let proof_bytes = merkle_root.to_vec();

    Ok(StarkProof {
        proof_bytes,
        public_inputs,
        metadata: ProofMetadata {
            anonymity_set_size: anonymity_set.len(),
            security_level: security_str.to_string(),
            proof_size_bytes: merkle_root.len(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_generation() {
        let witness = StarkWitness {
            sk_spend: [1u8; 32],
            sk_view: [2u8; 32],
            commitment: [42u8; 32],
            network_id: 1,
            tx_version: 2,
            epoch: 1000,
        };

        // Create anonymity set with witness commitment
        let mut anonymity_set = vec![[0u8; 32]; 64];
        anonymity_set[10] = witness.commitment;

        let config = ProverConfig::default();
        let proof = generate_proof(witness, &anonymity_set, config).expect("proof generation");

        assert_eq!(proof.metadata.anonymity_set_size, 64);
        assert_eq!(proof.metadata.security_level, "standard");
        assert_eq!(proof.proof_bytes.len(), 32); // Trace commitment (32 bytes)
        
        // Verify nullifier and spend tag are non-zero
        assert_ne!(proof.public_inputs.nullifier.0, [0u8; 32]);
        assert_ne!(proof.public_inputs.spend_tag.0, [0u8; 32]);
    }

    #[test]
    fn test_rejects_small_anonymity_set() {
        let witness = StarkWitness {
            sk_spend: [1u8; 32],
            sk_view: [2u8; 32],
            commitment: [42u8; 32],
            network_id: 1,
            tx_version: 2,
            epoch: 1000,
        };

        let anonymity_set = vec![[42u8; 32]; 16]; // Too small
        let config = ProverConfig::default();
        let result = generate_proof(witness, &anonymity_set, config);

        assert!(matches!(result, Err(ProverError::AnonymitySetTooSmall(16))));
    }

    #[test]
    fn test_rejects_missing_commitment() {
        let witness = StarkWitness {
            sk_spend: [1u8; 32],
            sk_view: [2u8; 32],
            commitment: [42u8; 32],
            network_id: 1,
            tx_version: 2,
            epoch: 1000,
        };

        let anonymity_set = vec![[0u8; 32]; 64]; // Doesn't contain witness.commitment
        let config = ProverConfig::default();
        let result = generate_proof(witness, &anonymity_set, config);

        assert!(matches!(result, Err(ProverError::InvalidCommitment)));
    }
}
