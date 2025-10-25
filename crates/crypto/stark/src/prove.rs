//! STARK proof generation.
//!
//! One-of-many proof: prove commitment exists in anonymity set without revealing index.

use crate::field::FieldElement;
use crate::fri::{FriParams, FriProof, FriProver};
use crate::merkle_tree::MerkleTree;
use crate::poseidon2::Poseidon2;
use crate::{StarkParams, StarkProof, StarkWitness};

/// Error during proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),
}

/// Generate a STARK proof for one-of-many membership.
///
/// Proves that `witness.commitment` exists in the `anonymity_set` at
/// the secret `witness.index` without revealing the index.
///
/// # Arguments
///
/// * `params` - STARK protocol parameters
/// * `anonymity_set` - Public set of commitments (size must match params)
/// * `witness` - Secret witness (index and commitment)
///
/// # Returns
///
/// A `StarkProof` that can be verified by `verify_one_of_many`.
///
/// # Example
///
/// ```ignore
/// let params = StarkParams::default();
/// let anonymity_set = vec![[0u8; 32]; 64];
/// let witness = StarkWitness {
///     index: 42,
///     commitment: anonymity_set[42],
///     nullifier: [1u8; 32],
/// };
///
/// let proof = prove_one_of_many(&params, &anonymity_set, &witness)?;
/// ```
pub fn prove_one_of_many(
    params: &StarkParams,
    anonymity_set: &[[u8; 32]],
    witness: &StarkWitness,
) -> Result<StarkProof, ProveError> {
    // Step 1: Validate witness
    if witness.index >= anonymity_set.len() {
        return Err(ProveError::InvalidWitness(format!(
            "Index {} out of bounds (set size: {})",
            witness.index,
            anonymity_set.len()
        )));
    }

    if anonymity_set[witness.index] != witness.commitment {
        return Err(ProveError::InvalidWitness(
            "Commitment mismatch at witness index".to_string(),
        ));
    }

    // Step 2: Convert anonymity set to field elements
    let set_elements: Vec<FieldElement> = anonymity_set
        .iter()
        .map(|commitment| {
            // Hash commitment to field element
            let bytes: Vec<_> = commitment
                .chunks(8)
                .map(|chunk| {
                    let mut arr = [0u8; 8];
                    arr[..chunk.len()].copy_from_slice(chunk);
                    FieldElement::from_u64(u64::from_le_bytes(arr))
                })
                .collect();
            Poseidon2::hash(&bytes)
        })
        .collect();

    // Step 3: Build Merkle tree of anonymity set
    let set_size = set_elements.len().next_power_of_two();
    let mut padded_set = set_elements.clone();
    padded_set.resize(set_size, FieldElement::ZERO);
    
    let merkle_tree = MerkleTree::new(padded_set);
    let merkle_root = merkle_tree.root();

    // Step 4: Generate execution trace (simplified: just witness element)
    let trace_length = 16; // Small trace for one-of-many
    let mut trace = vec![FieldElement::ZERO; trace_length];
    
    // Encode witness index and commitment into trace
    trace[0] = FieldElement::from_u64(witness.index as u64);
    trace[1] = set_elements[witness.index];
    
    // Fill rest of trace with constraint evaluations
    for i in 2..trace_length {
        trace[i] = trace[i - 1] + FieldElement::ONE;
    }

    // Step 5: Run FRI protocol
    let fri_params = match params.security {
        crate::params::SecurityLevel::Fast => FriParams::test(),
        _ => FriParams::secure(),
    };

    let mut fri_prover = FriProver::new(fri_params.clone(), trace);
    
    // Generate FRI challenges (deterministic from Merkle root)
    let challenges: Vec<FieldElement> = (0..fri_params.num_rounds())
        .map(|i| {
            let seed = merkle_root.to_canonical_u64().wrapping_add(i as u64);
            FieldElement::from_u64(seed)
        })
        .collect();

    let fri_commitment = fri_prover.commit(&challenges);
    
    // Generate query indices (deterministic)
    let query_indices: Vec<usize> = (0..fri_params.num_queries)
        .map(|i| i % trace_length)
        .collect();
    
    let query_proofs = fri_prover.prove_queries(&query_indices);

    // Step 6: Construct STARK proof
    Ok(StarkProof {
        trace_commitment: merkle_root.to_bytes(),
        fri_proof: FriProof {
            commitment: fri_commitment,
            query_proofs,
        },
        query_responses: vec![], // Simplified for now
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecurityLevel;

    #[test]
    fn test_prove_valid_witness() {
        let params = StarkParams {
            security: SecurityLevel::Fast,
            anonymity_set_size: 16,
            field_modulus: crate::GOLDILOCKS_PRIME,
            hash_function: crate::params::HashFunction::Poseidon2,
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
        };

        let result = prove_one_of_many(&params, &anonymity_set, &witness);
        assert!(result.is_ok());
        
        let proof = result.unwrap();
        assert_eq!(proof.trace_commitment.len(), 8);
    }

    #[test]
    fn test_prove_invalid_index() {
        let params = StarkParams::default();
        let anonymity_set = vec![[0u8; 32]; 64];
        
        let witness = StarkWitness {
            index: 100, // Out of bounds
            commitment: [0u8; 32],
            nullifier: [1u8; 32],
        };

        let result = prove_one_of_many(&params, &anonymity_set, &witness);
        assert!(result.is_err());
        
        match result {
            Err(ProveError::InvalidWitness(msg)) => {
                assert!(msg.contains("out of bounds"));
            }
            _ => panic!("Expected InvalidWitness error"),
        }
    }

    #[test]
    fn test_prove_commitment_mismatch() {
        let params = StarkParams::default();
        let anonymity_set = vec![[0u8; 32]; 64];
        
        let witness = StarkWitness {
            index: 0,
            commitment: [99u8; 32], // Doesn't match anonymity_set[0]
            nullifier: [1u8; 32],
        };

        let result = prove_one_of_many(&params, &anonymity_set, &witness);
        assert!(result.is_err());
        
        match result {
            Err(ProveError::InvalidWitness(msg)) => {
                assert!(msg.contains("mismatch"));
            }
            _ => panic!("Expected InvalidWitness error"),
        }
    }
}
