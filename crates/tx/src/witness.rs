//! Transaction version 2 witness data (STARK privacy).
//!
//! Adds nullifier and spend tag fields for anonymous spending.

use serde::{Deserialize, Serialize};

/// Nullifier prevents double-spending without revealing which UTXO was spent.
///
/// Construction: `Poseidon2("NULLIF" || sk_spend || commitment || net_id || tx_version)`
///
/// Properties:
/// - Deterministic (same input → same nullifier)
/// - Unlinkable (cannot correlate with public key or commitment)
/// - One-of-many proof ensures nullifier matches a valid UTXO
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Create a new nullifier from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get nullifier bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Spend tag enables wallet scanning without revealing spending patterns.
///
/// Construction: `Poseidon2("TAG" || sk_view || commitment || epoch)`
///
/// Properties:
/// - Wallet can detect spends by scanning tags with sk_view
/// - Observers cannot link tags to specific UTXOs
/// - Epoch binds tag to a time period (prevents precomputation)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpendTag(pub [u8; 32]);

impl SpendTag {
    /// Create a new spend tag from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get spend tag bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Compute nullifier for a confidential spend.
///
/// # Arguments
///
/// * `sk_spend` - Secret spend key
/// * `commitment` - Pedersen commitment to the output being spent
/// * `net_id` - Network identifier (mainnet/testnet)
/// * `tx_version` - Transaction version (ensures uniqueness across versions)
///
/// # Returns
///
/// A 32-byte nullifier that prevents double-spending.
///
/// # Example
///
/// ```ignore
/// let sk_spend = [0u8; 32];
/// let commitment = [1u8; 32];
/// let nullifier = compute_nullifier(&sk_spend, &commitment, 1, 2);
/// ```
pub fn compute_nullifier(
    _sk_spend: &[u8; 32],
    _commitment: &[u8; 32],
    _net_id: u8,
    _tx_version: u16,
) -> Nullifier {
    // TODO: Implement Poseidon2 hash in Step 4 (after STARK arith module)
    // For now, return placeholder
    todo!("Poseidon2 implementation in Step 4")
}

/// Compute spend tag for wallet scanning.
///
/// # Arguments
///
/// * `sk_view` - Secret view key
/// * `commitment` - Pedersen commitment to the output being spent
/// * `epoch` - Current epoch (block height / 1000)
///
/// # Returns
///
/// A 32-byte spend tag for wallet scanning.
///
/// # Example
///
/// ```ignore
/// let sk_view = [0u8; 32];
/// let commitment = [1u8; 32];
/// let epoch = 42;
/// let tag = compute_spend_tag(&sk_view, &commitment, epoch);
/// ```
pub fn compute_spend_tag(_sk_view: &[u8; 32], _commitment: &[u8; 32], _epoch: u64) -> SpendTag {
    // TODO: Implement Poseidon2 hash in Step 4
    // For now, return placeholder
    todo!("Poseidon2 implementation in Step 4")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_construction() {
        let nullifier = Nullifier::new([42u8; 32]);
        assert_eq!(nullifier.as_bytes()[0], 42);
        assert_eq!(nullifier.as_bytes().len(), 32);
    }

    #[test]
    fn test_spend_tag_construction() {
        let tag = SpendTag::new([99u8; 32]);
        assert_eq!(tag.as_bytes()[0], 99);
        assert_eq!(tag.as_bytes().len(), 32);
    }

    #[test]
    fn test_nullifier_equality() {
        let n1 = Nullifier([1u8; 32]);
        let n2 = Nullifier([1u8; 32]);
        let n3 = Nullifier([2u8; 32]);

        assert_eq!(n1, n2);
        assert_ne!(n1, n3);
    }

    #[test]
    fn test_spend_tag_equality() {
        let t1 = SpendTag([1u8; 32]);
        let t2 = SpendTag([1u8; 32]);
        let t3 = SpendTag([2u8; 32]);

        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_nullifier_serialization() {
        let nullifier = Nullifier([42u8; 32]);
        let json = serde_json::to_string(&nullifier).unwrap();
        let deserialized: Nullifier = serde_json::from_str(&json).unwrap();

        assert_eq!(nullifier, deserialized);
    }

    #[test]
    fn test_spend_tag_serialization() {
        let tag = SpendTag([99u8; 32]);
        let json = serde_json::to_string(&tag).unwrap();
        let deserialized: SpendTag = serde_json::from_str(&json).unwrap();

        assert_eq!(tag, deserialized);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_compute_nullifier_placeholder() {
        let _ = compute_nullifier(&[0u8; 32], &[1u8; 32], 1, 2);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_compute_spend_tag_placeholder() {
        let _ = compute_spend_tag(&[0u8; 32], &[1u8; 32], 42);
    }
}
