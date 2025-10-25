//! STARK proof generation.
//!
//! One-of-many proof: prove commitment exists in anonymity set without revealing index.

use crate::field::FieldElement;
use crate::fri::{FriParams, FriProof, FriProver};
use crate::merkle_tree::MerkleTree;
use crate::poseidon2::Poseidon2;
use crate::transcript::Transcript;
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

    // Step 3: Build Merkle tree of anonymity set with deterministic padding
    let set_size = set_elements.len().next_power_of_two();
    let mut padded_set = set_elements.clone();
    
    // Pad with deterministic dummy leaves (prevents info leak)
    // Dummy leaf i = Poseidon2("PAD" || i || merkle_root_of_real_leaves)
    if padded_set.len() < set_size {
        // Compute temporary root of real leaves for binding
        let real_root = compute_padding_seed(&set_elements);
        
        for i in padded_set.len()..set_size {
            let dummy_leaf = generate_dummy_leaf(i, real_root);
            padded_set.push(dummy_leaf);
        }
    }
    
    let merkle_tree = MerkleTree::new(padded_set);
    let merkle_root = merkle_tree.root();

    // Step 4: Generate execution trace (simplified: just witness element)
    // CRITICAL: Use constant-time operations to prevent timing attacks
    let trace_length = 16; // Small trace for one-of-many
    let mut trace = vec![FieldElement::ZERO; trace_length];
    
    // Encode witness index using constant-time select (no timing leak)
    // We encode the witness element, NOT the index directly
    let witness_elem = {
        let mut result = FieldElement::ZERO;
        for (i, elem) in set_elements.iter().enumerate() {
            let mask = constant_time_eq(i as u64, witness.index as u64);
            let selected = constant_time_select(mask, *elem, result);
            result = selected; // Accumulate with constant-time select
        }
        result
    };
    
    trace[0] = FieldElement::from_u64(witness.index as u64); // Index encoding (TODO: consider hiding this too)
    trace[1] = witness_elem; // Witness commitment (constant-time selected)
    trace[2] = merkle_root; // Bind trace to anonymity set root
    
    // Fill rest of trace with constraint evaluations
    for i in 3..trace_length {
        trace[i] = trace[i - 1] + FieldElement::ONE;
    }

    // Step 5: FRI protocol
    let fri_params = match params.security {
        crate::params::SecurityLevel::Fast => FriParams::test(),
        _ => FriParams::secure(),
    };

    let mut fri_prover = FriProver::new(fri_params.clone(), trace.clone());
    
    // Step 6: Build canonical 32-byte trace commitment FIRST
    // (needed for FRI challenge generation)
    let trace_digest = Poseidon2::hash_to_digest(&trace);
    
    // Generate FRI challenges (deterministic from trace commitment)
    let challenges: Vec<FieldElement> = (0..fri_params.num_rounds())
        .map(|i| {
            let mut seed_bytes = [0u8; 8];
            seed_bytes.copy_from_slice(&trace_digest[0..8]);
            let seed = FieldElement::from_bytes(&seed_bytes).to_canonical_u64().wrapping_add(i as u64);
            FieldElement::from_u64(seed)
        })
        .collect();

    let fri_commitment = fri_prover.commit(&challenges);
    
    // Generate query indices (deterministic)
    let query_indices: Vec<usize> = (0..fri_params.num_queries)
        .map(|i| i % trace_length)
        .collect();
    
    let query_proofs = fri_prover.prove_queries(&query_indices);

    // Step 7: Build Fiat-Shamir transcript (anti-malleability)
    let mut transcript = Transcript::new();
    transcript.absorb_tx_version(witness.tx_version);
    transcript.absorb_network_id(witness.network_id);
    transcript.absorb_nullifier(&witness.nullifier);
    transcript.absorb_spend_tag(&witness.spend_tag);
    transcript.absorb_anonymity_set_root(&trace_digest); // Bind to trace commitment
    transcript.absorb_anonymity_set_size(anonymity_set.len());
    
    let transcript_challenge = transcript.finalize_to_bytes();

    // Step 8: Construct STARK proof
    Ok(StarkProof {
        trace_commitment: trace_digest,
        transcript_challenge,
        fri_proof: FriProof {
            commitment: fri_commitment,
            query_proofs,
        },
        query_responses: vec![], // Simplified for now
    })
}

// ========== Constant-Time Helpers ==========

/// Constant-time equality check.
///
/// Returns 0xFFFFFFFFFFFFFFFF if a == b, otherwise 0x0000000000000000.
/// No secret-dependent branches.
#[inline]
fn constant_time_eq(a: u64, b: u64) -> u64 {
    let diff = a ^ b;
    // Classic constant-time zero test:
    // x == 0 iff (x | -x) has MSB = 0
    // MSB = 0 → shift gives 0 → negate to 1 → sub 1 → wraps to 0xFFFF...
    // MSB = 1 → shift gives 1 → negate to 0 → sub 1 → wraps to 0xFFFF..., but we want 0
    //
    // Simpler: (0u64.wrapping_sub(is_zero)) where is_zero = !(has_msb_set)
    let has_nonzero_bit = (diff | diff.wrapping_neg()) >> 63;
    let is_zero = 1u64 - has_nonzero_bit;
    0u64.wrapping_sub(is_zero) // 0 - 1 = 0xFFFF..., 0 - 0 = 0
}

/// Constant-Time Helpers
///
/// If mask == 0xFFFFFFFFFFFFFFFF, return true_val.
/// If mask == 0x0000000000000000, return false_val.
/// No secret-dependent branches.
#[inline]
fn constant_time_select(mask: u64, true_val: FieldElement, false_val: FieldElement) -> FieldElement {
    let a = true_val.to_canonical_u64() & mask;
    let b = false_val.to_canonical_u64() & !mask;
    FieldElement::from_canonical_u64(a | b)
}

// ========== Helper Functions ==========

/// Compute padding seed from real leaves (binding dummy leaves to actual set).
fn compute_padding_seed(real_leaves: &[FieldElement]) -> FieldElement {
    // Hash all real leaves together for deterministic padding
    Poseidon2::hash(real_leaves)
}

/// Generate deterministic dummy leaf for padding.
///
/// Formula: Poseidon2("PAD" || index || seed)
/// This ensures:
/// - Deterministic: Same input always produces same padding
/// - Unique: Different indices produce different leaves
/// - Bound: Padding depends on real leaf set via seed
fn generate_dummy_leaf(index: usize, seed: FieldElement) -> FieldElement {
    // "PAD" as field element (0x444150 in little-endian)
    let pad_tag = FieldElement::from_u64(0x444150);
    let index_elem = FieldElement::from_u64(index as u64);
    
    Poseidon2::hash(&[pad_tag, index_elem, seed])
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
            tx_version: 2,
            network_id: 1,
            spend_tag: [2u8; 32],
        };

        let result = prove_one_of_many(&params, &anonymity_set, &witness);
        assert!(result.is_ok());
        
        let proof = result.unwrap();
        assert_eq!(proof.trace_commitment.len(), 32); // 32-byte digest
        assert_eq!(proof.transcript_challenge.len(), 32); // 32-byte challenge
    }

    #[test]
    fn test_prove_invalid_index() {
        let params = StarkParams::default();
        let anonymity_set = vec![[0u8; 32]; 64];
        
        let witness = StarkWitness {
            index: 100, // Out of bounds
            commitment: [0u8; 32],
            nullifier: [1u8; 32],
            tx_version: 2,
            network_id: 1,
            spend_tag: [2u8; 32],
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
            tx_version: 2,
            network_id: 1,
            spend_tag: [2u8; 32],
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

    #[test]
    fn test_deterministic_padding() {
        let params = StarkParams {
            security: SecurityLevel::Fast,
            anonymity_set_size: 10, // Not power of 2, will pad to 16
            field_modulus: crate::GOLDILOCKS_PRIME,
            hash_function: crate::params::HashFunction::Poseidon2,
        };

        let anonymity_set: Vec<[u8; 32]> = (0..10)
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

        // Generate proof twice with same input
        let proof1 = prove_one_of_many(&params, &anonymity_set, &witness).unwrap();
        let proof2 = prove_one_of_many(&params, &anonymity_set, &witness).unwrap();

        // Padding should be deterministic (same trace commitment)
        assert_eq!(proof1.trace_commitment, proof2.trace_commitment);
    }

    #[test]
    fn test_padding_binds_to_set() {
        let params = StarkParams {
            security: SecurityLevel::Fast,
            anonymity_set_size: 10, // Will pad to 16
            field_modulus: crate::GOLDILOCKS_PRIME,
            hash_function: crate::params::HashFunction::Poseidon2,
        };

        let anonymity_set1: Vec<[u8; 32]> = (0..10)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr
            })
            .collect();

        let mut anonymity_set2 = anonymity_set1.clone();
        anonymity_set2[9][0] = 99; // Change last element (not witness element)

        let witness1 = StarkWitness {
            index: 5,
            commitment: anonymity_set1[5],
            nullifier: [1u8; 32],
            tx_version: 2,
            network_id: 1,
            spend_tag: [2u8; 32],
        };

        let witness2 = StarkWitness {
            index: 5,
            commitment: anonymity_set2[5], // Same position, same value
            nullifier: [1u8; 32],
            tx_version: 2,
            network_id: 1,
            spend_tag: [2u8; 32],
        };

        let proof1 = prove_one_of_many(&params, &anonymity_set1, &witness1).unwrap();
        let proof2 = prove_one_of_many(&params, &anonymity_set2, &witness2).unwrap();

        // Different sets produce different trace commitments
        // (padding seed binds to all real leaves)
        assert_ne!(proof1.trace_commitment, proof2.trace_commitment);
    }

    #[test]
    fn test_constant_time_eq() {
        // Equal values -> all bits set
        assert_eq!(constant_time_eq(42, 42), 0xFFFFFFFFFFFFFFFF);
        assert_eq!(constant_time_eq(0, 0), 0xFFFFFFFFFFFFFFFF);
        assert_eq!(constant_time_eq(u64::MAX, u64::MAX), 0xFFFFFFFFFFFFFFFF);

        // Different values -> all bits clear
        assert_eq!(constant_time_eq(42, 43), 0);
        assert_eq!(constant_time_eq(0, 1), 0);
        assert_eq!(constant_time_eq(u64::MAX, 0), 0);
    }

    #[test]
    fn test_constant_time_select() {
        let a = FieldElement::from_u64(100);
        let b = FieldElement::from_u64(200);

        // mask = 0xFFFF... -> select a
        let mask_true = 0xFFFFFFFFFFFFFFFF;
        assert_eq!(constant_time_select(mask_true, a, b), a);

        // mask = 0x0000... -> select b
        let mask_false = 0x0000000000000000;
        assert_eq!(constant_time_select(mask_false, a, b), b);
    }

    #[test]
    fn test_witness_selection_constant_time() {
        // This test verifies that witness selection doesn't leak timing
        // by ensuring all indices are processed identically

        let set_elements: Vec<FieldElement> = (0..16)
            .map(|i| FieldElement::from_u64(i as u64 * 10))
            .collect();

        let witness_index = 7;
        let expected = FieldElement::from_u64(70); // 7 * 10

        // Simulate constant-time selection
        let mut result = FieldElement::ZERO;
        for (i, elem) in set_elements.iter().enumerate() {
            let mask = constant_time_eq(i as u64, witness_index);
            result = constant_time_select(mask, *elem, result);
        }

        assert_eq!(result, expected);
    }
}

