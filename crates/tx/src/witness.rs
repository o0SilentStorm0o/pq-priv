//! Transaction version 2 witness data (STARK privacy).
//!
//! Adds nullifier and spend tag fields for anonymous spending.

use crypto_stark::{FieldElement, Poseidon2};
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
    sk_spend: &[u8; 32],
    commitment: &[u8; 32],
    net_id: u8,
    tx_version: u16,
) -> Nullifier {
    // Domain separation prefix
    let domain = b"NULLIF";
    
    // Convert inputs to field elements
    let mut inputs = Vec::new();
    
    // Add domain (split into field elements)
    for chunk in domain.chunks(8) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        inputs.push(FieldElement::from_u64(u64::from_le_bytes(bytes)));
    }
    
    // Add sk_spend (split into 4 field elements)
    for i in 0..4 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&sk_spend[i * 8..(i + 1) * 8]);
        inputs.push(FieldElement::from_u64(u64::from_le_bytes(bytes)));
    }
    
    // Add commitment (split into 4 field elements)
    for i in 0..4 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&commitment[i * 8..(i + 1) * 8]);
        inputs.push(FieldElement::from_u64(u64::from_le_bytes(bytes)));
    }
    
    // Add net_id and tx_version
    inputs.push(FieldElement::from_u64(net_id as u64));
    inputs.push(FieldElement::from_u64(tx_version as u64));
    
    // Hash with Poseidon2
    let hash = Poseidon2::hash(&inputs);
    
    // Convert field element to bytes (repeat to fill 32 bytes)
    let hash_bytes = hash.to_bytes();
    let mut result = [0u8; 32];
    for i in 0..4 {
        result[i * 8..(i + 1) * 8].copy_from_slice(&hash_bytes);
    }
    
    Nullifier(result)
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
pub fn compute_spend_tag(sk_view: &[u8; 32], commitment: &[u8; 32], epoch: u64) -> SpendTag {
    // Domain separation prefix
    let domain = b"TAG";
    
    // Convert inputs to field elements
    let mut inputs = Vec::new();
    
    // Add domain
    for chunk in domain.chunks(8) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        inputs.push(FieldElement::from_u64(u64::from_le_bytes(bytes)));
    }
    
    // Add sk_view (split into 4 field elements)
    for i in 0..4 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&sk_view[i * 8..(i + 1) * 8]);
        inputs.push(FieldElement::from_u64(u64::from_le_bytes(bytes)));
    }
    
    // Add commitment (split into 4 field elements)
    for i in 0..4 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&commitment[i * 8..(i + 1) * 8]);
        inputs.push(FieldElement::from_u64(u64::from_le_bytes(bytes)));
    }
    
    // Add epoch
    inputs.push(FieldElement::from_u64(epoch));
    
    // Hash with Poseidon2
    let hash = Poseidon2::hash(&inputs);
    
    // Convert field element to bytes (repeat to fill 32 bytes)
    let hash_bytes = hash.to_bytes();
    let mut result = [0u8; 32];
    for i in 0..4 {
        result[i * 8..(i + 1) * 8].copy_from_slice(&hash_bytes);
    }
    
    SpendTag(result)
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
    fn test_compute_nullifier() {
        let sk_spend = [0u8; 32];
        let commitment = [1u8; 32];
        
        let nullifier1 = compute_nullifier(&sk_spend, &commitment, 1, 2);
        let nullifier2 = compute_nullifier(&sk_spend, &commitment, 1, 2);
        
        // Deterministic
        assert_eq!(nullifier1, nullifier2);
        
        // Different inputs produce different nullifiers
        let nullifier3 = compute_nullifier(&sk_spend, &commitment, 2, 2);
        assert_ne!(nullifier1, nullifier3);
    }

    #[test]
    fn test_compute_spend_tag() {
        let sk_view = [0u8; 32];
        let commitment = [1u8; 32];
        
        let tag1 = compute_spend_tag(&sk_view, &commitment, 42);
        let tag2 = compute_spend_tag(&sk_view, &commitment, 42);
        
        // Deterministic
        assert_eq!(tag1, tag2);
        
        // Different epoch produces different tag
        let tag3 = compute_spend_tag(&sk_view, &commitment, 43);
        assert_ne!(tag1, tag3);
    }
}
