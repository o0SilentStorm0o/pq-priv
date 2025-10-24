//! STARK proof generation.
//!
//! Stub API for step 4 implementation.

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
    _params: &StarkParams,
    _anonymity_set: &[[u8; 32]],
    _witness: &StarkWitness,
) -> Result<StarkProof, ProveError> {
    // TODO: Step 4 implementation
    // 1. Validate witness index is in range
    // 2. Validate commitment matches anonymity_set[index]
    // 3. Generate execution trace
    // 4. Build Merkle tree of trace columns
    // 5. Run FRI protocol (commit, query, prove)
    // 6. Construct StarkProof

    todo!("prove_one_of_many implementation in step 4")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_prove_placeholder() {
        let params = StarkParams::default();
        let anonymity_set = vec![[0u8; 32]; 64];
        let witness = StarkWitness {
            index: 0,
            commitment: [0u8; 32],
            nullifier: [1u8; 32],
        };

        let _ = prove_one_of_many(&params, &anonymity_set, &witness);
    }
}
