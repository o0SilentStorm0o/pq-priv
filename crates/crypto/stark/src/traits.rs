//! STARK proof system traits.
//!
//! Defines generic interfaces for proving and verification, allowing future
//! backend swaps (e.g., GPU acceleration, zkVM integration).

use serde::{Deserialize, Serialize};

/// A STARK proof demonstrating one-of-many membership.
///
/// Proves that a committed value exists in an anonymity set of size N
/// without revealing the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProof {
    /// FRI commitment layers
    pub fri_commitments: Vec<[u8; 32]>,

    /// Query responses (trace columns + Merkle paths)
    pub query_proofs: Vec<QueryProof>,

    /// Final polynomial coefficients (after FRI reduction)
    pub final_poly: Vec<u64>,

    /// Proof metadata
    pub metadata: ProofMetadata,
}

/// Metadata for proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Anonymity set size (power of 2)
    pub anonymity_set_size: usize,

    /// Security level (number of FRI queries)
    pub num_queries: usize,

    /// Protocol version
    pub version: u8,
}

/// A single FRI query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProof {
    /// Trace evaluations at query position
    pub trace_values: Vec<u64>,

    /// Merkle authentication path
    pub merkle_path: Vec<[u8; 32]>,
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
    fn test_proof_metadata_serialization() {
        let metadata = ProofMetadata {
            anonymity_set_size: 64,
            num_queries: 27,
            version: 1,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: ProofMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.anonymity_set_size, 64);
        assert_eq!(deserialized.num_queries, 27);
    }

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
