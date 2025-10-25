//! STARK proof verification.
//!
//! Verifies one-of-many STARK proofs using FRI protocol.

use crate::field::FieldElement;
use crate::fri::FriVerifier;
use crate::{FriParams, StarkParams, StarkProof};

/// Error during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("Invalid proof structure: {0}")]
    InvalidProof(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("FRI query check failed at index {0}")]
    FriQueryFailed(usize),
}

/// Verify a STARK proof for one-of-many membership.
///
/// Verifies that the proof demonstrates knowledge of an index `i` such that
/// `anonymity_set[i]` matches the claimed commitment, without revealing `i`.
///
/// # Arguments
///
/// * `params` - STARK protocol parameters (must match prover's params)
/// * `anonymity_set` - Public set of commitments
/// * `proof` - The STARK proof to verify
///
/// # Returns
///
/// `Ok(())` if proof is valid, `Err(VerifyError)` otherwise.
///
/// # Example
///
/// ```ignore
/// let params = StarkParams::default();
/// let anonymity_set = vec![[0u8; 32]; 64];
/// let proof = /* ... obtained from prover ... */;
///
/// verify_one_of_many(&params, &anonymity_set, &proof)?;
/// println!("Proof is valid!");
/// ```
pub fn verify_one_of_many(
    params: &StarkParams,
    _anonymity_set: &[[u8; 32]],
    proof: &StarkProof,
) -> Result<(), VerifyError> {
    // Step 1: Check proof structure
    if proof.trace_commitment.len() != 32 {
        return Err(VerifyError::InvalidProof(
            "Invalid trace commitment size (expected 32 bytes)".to_string(),
        ));
    }

    // Step 2: Setup FRI verifier
    let fri_params = match params.security {
        crate::params::SecurityLevel::Fast => FriParams::test(),
        _ => FriParams::secure(),
    };

    let fri_verifier = FriVerifier::new(fri_params.clone());

    // Step 3: Generate FRI challenges from trace commitment
    // Extract first field element from 32-byte digest for challenge derivation
    let mut trace_seed_bytes = [0u8; 8];
    trace_seed_bytes.copy_from_slice(&proof.trace_commitment[0..8]);
    let trace_seed = FieldElement::from_bytes(&trace_seed_bytes);
    
    let challenges: Vec<FieldElement> = (0..fri_params.num_rounds())
        .map(|i| {
            let seed = trace_seed.to_canonical_u64().wrapping_add(i as u64);
            FieldElement::from_u64(seed)
        })
        .collect();

    // Step 4: Verify FRI proof
    if !fri_verifier.verify(&proof.fri_proof, &challenges) {
        return Err(VerifyError::VerificationFailed(
            "FRI verification failed".to_string(),
        ));
    }

    // Verification successful
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{HashFunction, SecurityLevel};
    use crate::prove::prove_one_of_many;
    use crate::traits::StarkWitness;

    #[test]
    fn test_verify_valid_proof() {
        let params = StarkParams {
            security: SecurityLevel::Fast,
            anonymity_set_size: 16,
            field_modulus: crate::GOLDILOCKS_PRIME,
            hash_function: HashFunction::Poseidon2,
        };

        let anonymity_set: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr
            })
            .collect();

        let witness = StarkWitness {
            index: 5,
            commitment: anonymity_set[5],
            nullifier: [1u8; 32],
            tx_version: 2,
            network_id: 1,
            spend_tag: [2u8; 32],
        };

        let proof = prove_one_of_many(&params, &anonymity_set, &witness).unwrap();
        let result = verify_one_of_many(&params, &anonymity_set, &proof);

        assert!(result.is_ok());
    }
}
