//! Wallet library for STARK-based privacy transactions.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod audit;
pub mod stark_prover;

pub use audit::{AuditError, AuditLevel, AuditPacket, create_audit_packet};
pub use stark_prover::{
    ProverConfig, ProverError, SecurityLevel, StarkProof, StarkWitness, generate_proof,
};
