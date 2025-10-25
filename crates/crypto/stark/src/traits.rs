//! STARK proof system traits.
//!
//! Defines generic interfaces for proving and verification, allowing future
//! backend swaps (e.g., GPU acceleration, zkVM integration).

use crate::fri::FriProof;
use serde::Serialize;

/// A STARK proof demonstrating one-of-many membership.
///
/// Proves that a committed value exists in an anonymity set of size N
/// without revealing the index.
#[derive(Debug, Clone, Serialize)]
pub struct StarkProof {
    /// Merkle root of execution trace
    pub trace_commitment: [u8; 8],

    /// FRI proof of low-degree polynomial
    #[serde(skip)]
    pub fri_proof: FriProof,

    /// Query responses (trace columns at query positions)
    pub query_responses: Vec<Vec<u64>>,
}

/// Witness data for STARK proof generation.
///
/// Contains the secret index and private witness values.
#[derive(Debug, Clone)]
pub struct StarkWitness {
    /// Secret index in anonymity set (0..N-1)
    pub index: usize,

    /// Commitment to the spent output
    pub commitment: [u8; 32],

    /// Nullifier (prevents double-spend detection)
    pub nullifier: [u8; 32],
}

/// Trait for STARK provable computations.
///
/// Implement this trait to define custom STARK circuits.
pub trait StarkProvable {
    /// Generate execution trace for the computation.
    fn generate_trace(&self, witness: &StarkWitness) -> Vec<Vec<u64>>;

    /// Define AIR constraints (Algebraic Intermediate Representation).
    fn constraints(&self) -> Vec<Constraint>;
}

/// A constraint in the AIR (Algebraic Intermediate Representation).
#[derive(Debug, Clone)]
pub struct Constraint {
    /// Polynomial expression
    pub expr: String, // TODO: Replace with proper AST in step 2

    /// Constraint degree
    pub degree: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_witness_construction() {
        let witness = StarkWitness {
            index: 42,
            commitment: [0u8; 32],
            nullifier: [1u8; 32],
        };

        assert_eq!(witness.index, 42);
        assert_ne!(witness.commitment, witness.nullifier);
    }
}
