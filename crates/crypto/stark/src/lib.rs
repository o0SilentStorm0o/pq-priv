//! # crypto-stark
//!
//! Transparent STARK one-of-many proofs for PQ-PRIV privacy.
//!
//! This crate provides Winterfell-style trait-based STARK proving system for
//! demonstrating that a committed output exists in an anonymity set without
//! revealing which one (one-of-many proof).
//!
//! ## Architecture
//!
//! - **Traits**: Generic proving/verification interfaces (Step 1)
//! - **Arithmetic**: Field operations, FFT, polynomial evaluation (Step 2)
//! - **Merkle**: Commitment trees for trace and FRI (Step 3)
//! - **Prover**: STARK trace generation and proof construction (Step 4)
//! - **Verifier**: FRI-based verification (Step 5)
//!
//! ## Security Parameters
//!
//! Default configuration provides ~100-bit security:
//! - Field: 64-bit prime (FRI-friendly)
//! - FRI reduction factor: 8
//! - Number of queries: 27
//! - Hash function: Poseidon2 (STARK-friendly)

pub mod arith;
pub mod batch;
pub mod field;
pub mod fri;
pub mod merkle;
pub mod merkle_tree;
pub mod params;
pub mod poseidon2;
pub mod prove;
pub mod traits;
pub mod transcript;
pub mod verify;

pub use field::{FieldElement, GOLDILOCKS_PRIME};
pub use fri::{FriCommitment, FriParams, FriProof, FriProver, FriVerifier};
pub use merkle_tree::{MerkleProof, MerkleTree};
pub use poseidon2::{Poseidon2, STATE_WIDTH};

pub use batch::{verify_batch, verify_batch_sequential, BatchVerifyResult, ProofContext};
pub use params::{SecurityLevel, StarkParams};
pub use prove::prove_one_of_many;
pub use traits::{StarkProof, StarkWitness};
pub use transcript::Transcript;
pub use verify::verify_one_of_many;

/// STARK library version for protocol compatibility
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_version() {
        // Verify version is set from Cargo.toml
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        println!("STARK library version: {}", VERSION);
    }
}
