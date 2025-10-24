//! Merkle tree operations for FRI commitments.
//!
//! Placeholder module for step 3 implementation.
//!
//! Will contain:
//! - Poseidon2 hash function
//! - Merkle tree construction and root computation
//! - Authentication path generation and verification

/// TODO: Implement Merkle tree in step 3
pub struct MerkleTree {
    _leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// TODO: Construct Merkle tree from leaves
    pub fn new(_leaves: Vec<[u8; 32]>) -> Self {
        todo!("Merkle tree construction in step 3")
    }

    /// TODO: Compute Merkle root
    pub fn root(&self) -> [u8; 32] {
        todo!("Merkle root computation in step 3")
    }

    /// TODO: Generate authentication path
    pub fn prove(&self, _index: usize) -> Vec<[u8; 32]> {
        todo!("Merkle proof generation in step 3")
    }
}

/// TODO: Verify Merkle authentication path
pub fn verify_merkle_path(
    _root: &[u8; 32],
    _leaf: &[u8; 32],
    _index: usize,
    _path: &[[u8; 32]],
) -> bool {
    todo!("Merkle verification in step 3")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_merkle_tree_placeholder() {
        let _tree = MerkleTree::new(vec![[0u8; 32]; 4]);
    }
}
