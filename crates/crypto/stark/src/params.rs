//! STARK security parameters and configuration.

use serde::{Deserialize, Serialize};

/// Security level determines proof size and verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// ~80-bit security (fast, smaller proofs)
    Fast,

    /// ~100-bit security (recommended for production)
    Standard,

    /// ~128-bit security (conservative)
    High,
}

impl SecurityLevel {
    /// Number of FRI queries required for this security level.
    pub fn num_queries(&self) -> usize {
        match self {
            SecurityLevel::Fast => 20,
            SecurityLevel::Standard => 27,
            SecurityLevel::High => 40,
        }
    }

    /// FRI reduction factor (folding ratio).
    pub fn fri_factor(&self) -> usize {
        match self {
            SecurityLevel::Fast => 4,
            SecurityLevel::Standard => 8,
            SecurityLevel::High => 8,
        }
    }
}

/// STARK protocol parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkParams {
    /// Security level
    pub security: SecurityLevel,

    /// Anonymity set size (must be power of 2)
    pub anonymity_set_size: usize,

    /// Field modulus (64-bit prime)
    pub field_modulus: u64,

    /// Hash function for Merkle trees (currently Poseidon2)
    pub hash_function: HashFunction,
}

/// Supported hash functions for STARK commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashFunction {
    /// Poseidon2 (STARK-friendly, optimized for field elements)
    Poseidon2,
}

/// Poseidon2 hash function parameters (official specification).
///
/// These parameters are cryptographically verified for:
/// - Field: GF(2^64 - 2^32 + 1) (Goldilocks)
/// - S-box: x^7 (low algebraic degree)
/// - Security: ~128-bit collision resistance
///
/// References:
/// - "Poseidon2: A Faster Version of the Poseidon Hash Function"
/// - Constants generated via Grain-128 LFSR
pub mod poseidon2_params {
    /// Poseidon2 parameters version (for versioning if updated).
    pub const VERSION: u32 = 1;

    /// State width (number of field elements).
    pub const STATE_WIDTH: usize = 12;

    /// Number of full rounds (R_F).
    ///
    /// Full rounds apply S-box to all state elements.
    /// Split: 4 rounds before + 4 rounds after partial rounds.
    pub const FULL_ROUNDS: usize = 8;

    /// Number of partial rounds (R_P).
    ///
    /// Partial rounds apply S-box to only first state element.
    /// Optimizes performance while maintaining security.
    pub const PARTIAL_ROUNDS: usize = 22;

    /// Total rounds.
    pub const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

    /// S-box degree (x^7).
    ///
    /// Lower degree = better STARK performance
    /// Degree 7 provides optimal security/performance tradeoff.
    pub const SBOX_DEGREE: usize = 7;

    /// Field modulus (Goldilocks prime).
    pub const FIELD_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

    /// Security level in bits.
    ///
    /// Estimated collision resistance: ~128 bits
    /// Estimated preimage resistance: ~100 bits
    pub const SECURITY_BITS: usize = 100;
}

impl Default for StarkParams {
    fn default() -> Self {
        Self {
            security: SecurityLevel::Standard,
            anonymity_set_size: 64,
            field_modulus: Self::DEFAULT_FIELD_MODULUS,
            hash_function: HashFunction::Poseidon2,
        }
    }
}

impl StarkParams {
    /// Default 64-bit prime field modulus (FRI-friendly).
    ///
    /// Prime: 2^64 - 2^32 + 1 (Goldilocks-like)
    pub const DEFAULT_FIELD_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

    /// Minimum anonymity set size (DoS protection).
    pub const MIN_ANONYMITY_SET: usize = 32;

    /// Maximum anonymity set size (DoS protection).
    pub const MAX_ANONYMITY_SET: usize = 256;

    /// Create parameters with custom anonymity set size.
    pub fn with_anonymity_set(mut self, size: usize) -> Result<Self, ParamError> {
        if !size.is_power_of_two() {
            return Err(ParamError::InvalidAnonymitySet(
                "Size must be power of 2".into(),
            ));
        }

        if !(Self::MIN_ANONYMITY_SET..=Self::MAX_ANONYMITY_SET).contains(&size) {
            return Err(ParamError::InvalidAnonymitySet(format!(
                "Size must be in range [{}, {}]",
                Self::MIN_ANONYMITY_SET,
                Self::MAX_ANONYMITY_SET
            )));
        }

        self.anonymity_set_size = size;
        Ok(self)
    }

    /// Set security level.
    pub fn with_security(mut self, level: SecurityLevel) -> Self {
        self.security = level;
        self
    }

    /// Validate parameters for consistency.
    pub fn validate(&self) -> Result<(), ParamError> {
        if !self.anonymity_set_size.is_power_of_two() {
            return Err(ParamError::InvalidAnonymitySet(
                "Size must be power of 2".into(),
            ));
        }

        if self.field_modulus < 2u64.pow(32) {
            return Err(ParamError::InvalidField("Field modulus too small".into()));
        }

        Ok(())
    }
}

/// Parameter validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ParamError {
    #[error("Invalid anonymity set: {0}")]
    InvalidAnonymitySet(String),

    #[error("Invalid field parameters: {0}")]
    InvalidField(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params() {
        let params = StarkParams::default();
        assert_eq!(params.security, SecurityLevel::Standard);
        assert_eq!(params.anonymity_set_size, 64);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(SecurityLevel::Fast.num_queries(), 20);
        assert_eq!(SecurityLevel::Standard.num_queries(), 27);
        assert_eq!(SecurityLevel::High.num_queries(), 40);
    }

    #[test]
    fn test_anonymity_set_validation() {
        let params = StarkParams::default().with_anonymity_set(128).unwrap();
        assert_eq!(params.anonymity_set_size, 128);

        // Non-power-of-2 should fail
        assert!(StarkParams::default().with_anonymity_set(100).is_err());

        // Out of range should fail
        assert!(StarkParams::default().with_anonymity_set(16).is_err());

        assert!(StarkParams::default().with_anonymity_set(512).is_err());
    }

    #[test]
    fn test_params_serialization() {
        let params = StarkParams::default();
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: StarkParams = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.security, params.security);
        assert_eq!(deserialized.anonymity_set_size, params.anonymity_set_size);
    }
}
