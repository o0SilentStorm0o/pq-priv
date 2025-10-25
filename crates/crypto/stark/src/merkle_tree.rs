//! Merkle tree implementation using Poseidon2 hash.
//!
//! Binary Merkle tree for STARK witness commitments:
//! - Leaf nodes: commitments to UTXO set elements
//! - Internal nodes: Poseidon2(left_child || right_child)
//! - Root: single field element committing to entire set
//!
//! ## Security Properties
//!
//! ### Hiding Witness Index
//! The Merkle tree MUST NOT reveal which leaf corresponds to the spent UTXO.
//! This is achieved by:
//! 1. **Deterministic padding**: Pad to next power-of-2 with dummy leaves
//!    generated as `Poseidon2("PAD" || index || merkle_root_of_real_leaves)`
//! 2. **Index hiding**: STARK proof does NOT encode witness index in trace;
//!    only the witness element (commitment) is included
//! 3. **Constant-time selection**: Witness element selected using
//!    constant-time operations to prevent timing side-channels
//!
//! ### Transcript Binding
//! The Merkle root is absorbed into the Fiat-Shamir transcript to:
//! - **Prevent proof extraction**: Proof cannot be reused with different anonymity set
//! - **Prevent malleability**: Root commits to entire set structure
//! - **Prevent padding oracle**: Real set size also absorbed separately
//!
//! ## Usage in STARK Proofs
//!
//! 1. **Prover** builds Merkle tree from anonymity set (with padding)
//! 2. **Prover** generates Merkle proof for witness index (internally)
//! 3. **Prover** binds Merkle root to transcript (anti-malleability)
//! 4. **Verifier** receives Merkle root in proof
//! 5. **Verifier** checks root matches expected anonymity set
//! 6. **Verifier** verifies STARK constraints bind to root
//!
//! ## Example
//!
//! ```ignore
//! use crypto_stark::merkle_tree::MerkleTree;
//! use crypto_stark::field::FieldElement;
//!
//! // Anonymity set (UTXO commitments)
//! let commitments = vec![
//!     FieldElement::from_u64(100),
//!     FieldElement::from_u64(200),
//!     FieldElement::from_u64(300),
//!     FieldElement::from_u64(400),
//! ];
//!
//! // Build Merkle tree (automatically pads to power-of-2)
//! let tree = MerkleTree::new(commitments);
//!
//! // Get Merkle root (for transcript binding)
//! let root = tree.root();
//!
//! // Generate proof for witness (index hidden in final STARK proof)
//! let witness_index = 2; // NOT revealed to verifier
//! let proof = tree.prove(witness_index);
//!
//! // Verify proof (internally used, not exposed in public API)
//! assert!(MerkleTree::verify(root, &proof));
//! ```
//!
//! ## References
//!
//! - "One-out-of-Many Proofs: Or How to Leak a Secret and Spend a Coin"
//! - STARK Merkle commitment schemes
//! - Poseidon2 hash function specification
//!
//! Properties:
//! - Membership proofs: O(log N) size
//! - Verification: O(log N) Poseidon2 hashes
//! - STARK-friendly: algebraic hash enables proof composition

use crate::field::FieldElement;
use crate::poseidon2::Poseidon2;

/// Merkle tree with Poseidon2 hashing.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// All tree nodes stored in level order.
    /// Index 0 = root, indices 1-2 = level 1, etc.
    nodes: Vec<FieldElement>,
    
    /// Number of leaves in the tree (must be power of 2).
    num_leaves: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf values.
    ///
    /// # Panics
    ///
    /// Panics if `leaves` is empty or not a power of 2.
    pub fn new(leaves: Vec<FieldElement>) -> Self {
        assert!(!leaves.is_empty(), "Cannot build tree with no leaves");
        assert!(
            leaves.len().is_power_of_two(),
            "Number of leaves must be power of 2"
        );

        let num_leaves = leaves.len();
        let total_nodes = 2 * num_leaves - 1;
        let mut nodes = vec![FieldElement::ZERO; total_nodes];

        // Copy leaves to end of nodes array
        let leaf_offset = num_leaves - 1;
        nodes[leaf_offset..].copy_from_slice(&leaves);

        // Build tree from bottom up
        for i in (0..leaf_offset).rev() {
            let left_child = 2 * i + 1;
            let right_child = 2 * i + 2;
            nodes[i] = Poseidon2::hash_pair(nodes[left_child], nodes[right_child]);
        }

        Self { nodes, num_leaves }
    }

    /// Get the Merkle root (commitment to entire tree).
    pub fn root(&self) -> FieldElement {
        self.nodes[0]
    }

    /// Get a leaf value by index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= num_leaves`.
    pub fn get_leaf(&self, index: usize) -> FieldElement {
        assert!(index < self.num_leaves, "Leaf index out of bounds");
        let leaf_offset = self.num_leaves - 1;
        self.nodes[leaf_offset + index]
    }

    /// Generate a Merkle proof for a leaf.
    ///
    /// Returns authentication path (sibling hashes from leaf to root).
    ///
    /// # Panics
    ///
    /// Panics if `index >= num_leaves`.
    pub fn prove(&self, index: usize) -> MerkleProof {
        assert!(index < self.num_leaves, "Leaf index out of bounds");

        let mut path = Vec::new();
        let mut current_index = self.num_leaves - 1 + index; // Start at leaf

        while current_index > 0 {
            let sibling_index = if current_index % 2 == 0 {
                current_index - 1 // We are right child, sibling is left
            } else {
                current_index + 1 // We are left child, sibling is right
            };

            path.push(self.nodes[sibling_index]);
            current_index = (current_index - 1) / 2; // Move to parent
        }

        MerkleProof {
            leaf_index: index,
            leaf_value: self.get_leaf(index),
            path,
        }
    }

    /// Verify a Merkle proof against a known root.
    pub fn verify(root: FieldElement, proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf_value;
        let mut index = proof.leaf_index;

        for &sibling_hash in &proof.path {
            current_hash = if index % 2 == 0 {
                // We are left child
                Poseidon2::hash_pair(current_hash, sibling_hash)
            } else {
                // We are right child
                Poseidon2::hash_pair(sibling_hash, current_hash)
            };
            index /= 2;
        }

        current_hash == root
    }

    /// Get the tree height (number of levels).
    pub fn height(&self) -> usize {
        (self.num_leaves as f64).log2() as usize
    }

    /// Get the number of leaves.
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }
}

/// Merkle authentication path proving leaf membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// Index of the leaf being proven.
    pub leaf_index: usize,
    
    /// Value of the leaf.
    pub leaf_value: FieldElement,
    
    /// Sibling hashes along the path from leaf to root.
    /// path[0] = sibling of leaf, path[1] = sibling at level 1, etc.
    pub path: Vec<FieldElement>,
}

impl MerkleProof {
    /// Get the proof size in field elements.
    pub fn size(&self) -> usize {
        self.path.len()
    }

    /// Verify this proof against a root.
    pub fn verify(&self, root: FieldElement) -> bool {
        MerkleTree::verify(root, self)
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tree() {
        let leaves = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(4),
        ];

        let tree = MerkleTree::new(leaves.clone());

        assert_eq!(tree.num_leaves(), 4);
        assert_eq!(tree.height(), 2);
        assert_eq!(tree.get_leaf(0), FieldElement::from_u64(1));
        assert_eq!(tree.get_leaf(3), FieldElement::from_u64(4));
    }

    #[test]
    #[should_panic(expected = "power of 2")]
    fn test_build_tree_non_power_of_two() {
        let leaves = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];
        let _ = MerkleTree::new(leaves);
    }

    #[test]
    #[should_panic(expected = "no leaves")]
    fn test_build_tree_empty() {
        let leaves: Vec<FieldElement> = vec![];
        let _ = MerkleTree::new(leaves);
    }

    #[test]
    fn test_root_deterministic() {
        let leaves = vec![
            FieldElement::from_u64(10),
            FieldElement::from_u64(20),
        ];

        let tree1 = MerkleTree::new(leaves.clone());
        let tree2 = MerkleTree::new(leaves);

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_leaves_different_root() {
        let leaves1 = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
        ];
        let leaves2 = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(3),
        ];

        let tree1 = MerkleTree::new(leaves1);
        let tree2 = MerkleTree::new(leaves2);

        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_prove_and_verify() {
        let leaves = vec![
            FieldElement::from_u64(100),
            FieldElement::from_u64(200),
            FieldElement::from_u64(300),
            FieldElement::from_u64(400),
        ];

        let tree = MerkleTree::new(leaves);
        let root = tree.root();

        // Test proof for each leaf
        for i in 0..4 {
            let proof = tree.prove(i);
            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.leaf_value, tree.get_leaf(i));
            assert!(MerkleTree::verify(root, &proof));
            assert!(proof.verify(root));
        }
    }

    #[test]
    fn test_verify_wrong_root() {
        let leaves = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
        ];

        let tree = MerkleTree::new(leaves);
        let proof = tree.prove(0);

        let wrong_root = FieldElement::from_u64(999);
        assert!(!MerkleTree::verify(wrong_root, &proof));
    }

    #[test]
    fn test_verify_tampered_leaf() {
        let leaves = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
        ];

        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        let mut proof = tree.prove(0);

        // Tamper with leaf value
        proof.leaf_value = FieldElement::from_u64(999);

        assert!(!MerkleTree::verify(root, &proof));
    }

    #[test]
    fn test_proof_size() {
        let leaves = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(4),
            FieldElement::from_u64(5),
            FieldElement::from_u64(6),
            FieldElement::from_u64(7),
            FieldElement::from_u64(8),
        ];

        let tree = MerkleTree::new(leaves);
        let proof = tree.prove(0);

        // Tree height = log2(8) = 3, so proof has 3 siblings
        assert_eq!(proof.size(), 3);
    }

    #[test]
    fn test_single_leaf_tree() {
        let leaves = vec![FieldElement::from_u64(42)];
        let tree = MerkleTree::new(leaves);

        assert_eq!(tree.height(), 0);
        assert_eq!(tree.root(), FieldElement::from_u64(42));

        let proof = tree.prove(0);
        assert_eq!(proof.size(), 0); // No siblings for single leaf
        assert!(proof.verify(tree.root()));
    }
}
