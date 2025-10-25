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
//! - **Traits**: Generic proving/verification interfaces
//! - **Field**: Goldilocks field arithmetic (64-bit prime)
//! - **Merkle**: Poseidon2-based commitment trees
//! - **Prover**: STARK trace generation and proof construction
//! - **Verifier**: FRI-based verification
//!
//! ## Security Parameters
//!
//! Default configuration provides ~100-bit security:
//! - Field: Goldilocks GF(2^64 - 2^32 + 1)
//! - FRI reduction factor: 8
//! - Number of queries: 100
//! - Hash function: Poseidon2 (12-state, 30 rounds)

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::float_cmp)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::inline_always)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::match_same_arms)]

pub mod batch;
pub mod field;
pub mod fri;
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
