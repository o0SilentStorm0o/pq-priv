//! Fiat-Shamir transcript for STARK proof binding.
//!
//! Provides cryptographic binding of proofs to transaction context,
//! preventing proof malleability and replay attacks.

use crate::field::FieldElement;
use crate::poseidon2::Poseidon2;

/// Domain separation tag for PQ-PRIV STARK proofs.
const DOMAIN_SEP: &str = "PQPRIV-STARK-V2";

/// Fiat-Shamir transcript builder for STARK proofs.
///
/// Binds proof to transaction context using Poseidon2 hash.
/// Prevents proof extraction and replay across transactions.
#[derive(Clone, Debug)]
pub struct Transcript {
    state: Vec<FieldElement>,
}

impl Transcript {
    /// Create new transcript with domain separation.
    pub fn new() -> Self {
        // Initialize with domain separator hash
        let domain_bytes = DOMAIN_SEP.as_bytes();
        let domain_elements: Vec<FieldElement> = domain_bytes
            .chunks(8)
            .map(|chunk| {
                let mut arr = [0u8; 8];
                arr[..chunk.len()].copy_from_slice(chunk);
                FieldElement::from_u64(u64::from_le_bytes(arr))
            })
            .collect();

        Self {
            state: vec![Poseidon2::hash(&domain_elements)],
        }
    }

    /// Absorb transaction version (for upgrade compatibility).
    pub fn absorb_tx_version(&mut self, version: u16) {
        self.state.push(FieldElement::from_u64(version as u64));
    }

    /// Absorb network ID (prevents cross-chain replay).
    pub fn absorb_network_id(&mut self, net_id: u8) {
        self.state.push(FieldElement::from_u64(net_id as u64));
    }

    /// Absorb nullifier (binds to specific spend).
    pub fn absorb_nullifier(&mut self, nullifier: &[u8; 32]) {
        let elements = bytes_to_field_elements(nullifier);
        self.state.extend(elements);
    }

    /// Absorb spend tag (binds to epoch/audit context).
    pub fn absorb_spend_tag(&mut self, spend_tag: &[u8; 32]) {
        let elements = bytes_to_field_elements(spend_tag);
        self.state.extend(elements);
    }

    /// Absorb anonymity set root (binds to UTXO set state).
    pub fn absorb_anonymity_set_root(&mut self, root: &[u8; 32]) {
        let elements = bytes_to_field_elements(root);
        self.state.extend(elements);
    }

    /// Absorb anonymity set size (prevents padding oracle attacks).
    pub fn absorb_anonymity_set_size(&mut self, size: usize) {
        self.state.push(FieldElement::from_u64(size as u64));
    }

    /// Finalize transcript and extract challenge.
    pub fn finalize(&self) -> FieldElement {
        Poseidon2::hash(&self.state)
    }

    /// Finalize transcript and extract 32-byte challenge.
    pub fn finalize_to_bytes(&self) -> [u8; 32] {
        Poseidon2::hash_to_digest(&self.state)
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert 32-byte array to field elements (4 elements of 8 bytes each).
fn bytes_to_field_elements(bytes: &[u8; 32]) -> Vec<FieldElement> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(chunk);
            FieldElement::from_u64(u64::from_le_bytes(arr))
        })
        .collect()
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_domain_separation() {
        let t1 = Transcript::new();
        let t2 = Transcript::new();

        // Same initial state
        assert_eq!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_tx_version() {
        let mut t1 = Transcript::new();
        t1.absorb_tx_version(1);

        let mut t2 = Transcript::new();
        t2.absorb_tx_version(2);

        // Different versions produce different challenges
        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_network_id() {
        let mut t1 = Transcript::new();
        t1.absorb_network_id(1);

        let mut t2 = Transcript::new();
        t2.absorb_network_id(2);

        // Different network IDs produce different challenges
        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_nullifier() {
        let mut t1 = Transcript::new();
        t1.absorb_nullifier(&[1u8; 32]);

        let mut t2 = Transcript::new();
        t2.absorb_nullifier(&[2u8; 32]);

        // Different nullifiers produce different challenges
        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_spend_tag() {
        let mut t1 = Transcript::new();
        t1.absorb_spend_tag(&[1u8; 32]);

        let mut t2 = Transcript::new();
        t2.absorb_spend_tag(&[2u8; 32]);

        // Different spend tags produce different challenges
        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_anonymity_set_size() {
        let mut t1 = Transcript::new();
        t1.absorb_anonymity_set_size(64);

        let mut t2 = Transcript::new();
        t2.absorb_anonymity_set_size(128);

        // Different set sizes produce different challenges
        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_order_matters() {
        let mut t1 = Transcript::new();
        t1.absorb_nullifier(&[1u8; 32]);
        t1.absorb_spend_tag(&[2u8; 32]);

        let mut t2 = Transcript::new();
        t2.absorb_spend_tag(&[2u8; 32]);
        t2.absorb_nullifier(&[1u8; 32]);

        // Order matters (prevents permutation attacks)
        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_finalize_deterministic() {
        let mut t = Transcript::new();
        t.absorb_tx_version(2);
        t.absorb_network_id(1);
        t.absorb_nullifier(&[42u8; 32]);

        let challenge1 = t.finalize();
        let challenge2 = t.finalize();

        // Finalization is deterministic
        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_transcript_to_bytes() {
        let mut t = Transcript::new();
        t.absorb_tx_version(2);
        t.absorb_network_id(1);

        let bytes = t.finalize_to_bytes();
        assert_eq!(bytes.len(), 32);

        // Non-zero output
        assert_ne!(bytes, [0u8; 32]);
    }
}
