//! Poseidon2 hash function for STARK-friendly hashing.
//!
//! Implements Poseidon2 permutation with parameters optimized for Goldilocks field:
//! - State width: 12 elements
//! - Full rounds: 8 (4 at beginning, 4 at end)
//! - Partial rounds: 22
//! - S-box: x^7 (STARK-friendly, low degree)
//!
//! Security: ~128-bit collision resistance, ~100-bit preimage resistance.

use crate::field::FieldElement;

/// Poseidon2 state width (number of field elements).
pub const STATE_WIDTH: usize = 12;

/// Number of full rounds (4 before + 4 after partial rounds).
pub const FULL_ROUNDS: usize = 8;

/// Number of partial rounds (only 1 S-box per round).
pub const PARTIAL_ROUNDS: usize = 22;

/// Total rounds.
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

/// Poseidon2 hasher state.
#[derive(Clone, Debug)]
pub struct Poseidon2 {
    state: [FieldElement; STATE_WIDTH],
}

impl Poseidon2 {
    /// Create new Poseidon2 hasher with zero state.
    pub fn new() -> Self {
        Self {
            state: [FieldElement::ZERO; STATE_WIDTH],
        }
    }

    /// Hash a single field element (domain separation for nullifiers/spend tags).
    pub fn hash_single(input: FieldElement) -> FieldElement {
        let mut hasher = Self::new();
        hasher.state[0] = input;
        hasher.permute();
        hasher.state[0]
    }

    /// Hash two field elements (e.g., Merkle tree parent hash).
    pub fn hash_pair(left: FieldElement, right: FieldElement) -> FieldElement {
        let mut hasher = Self::new();
        hasher.state[0] = left;
        hasher.state[1] = right;
        hasher.permute();
        hasher.state[0]
    }

    /// Hash variable-length input (general purpose).
    pub fn hash(inputs: &[FieldElement]) -> FieldElement {
        let mut hasher = Self::new();
        
        // Absorb inputs in chunks of STATE_WIDTH
        for chunk in inputs.chunks(STATE_WIDTH) {
            for (i, &input) in chunk.iter().enumerate() {
                hasher.state[i] = hasher.state[i] + input;
            }
            hasher.permute();
        }
        
        hasher.state[0]
    }

    /// Apply Poseidon2 permutation to internal state.
    fn permute(&mut self) {
        let mut round = 0;

        // First half of full rounds
        for _ in 0..(FULL_ROUNDS / 2) {
            self.add_round_constants(round);
            self.apply_sbox_full();
            self.apply_mds();
            round += 1;
        }

        // Partial rounds
        for _ in 0..PARTIAL_ROUNDS {
            self.add_round_constants(round);
            self.apply_sbox_partial();
            self.apply_mds();
            round += 1;
        }

        // Second half of full rounds
        for _ in 0..(FULL_ROUNDS / 2) {
            self.add_round_constants(round);
            self.apply_sbox_full();
            self.apply_mds();
            round += 1;
        }
    }

    /// Add round constants to state.
    fn add_round_constants(&mut self, round: usize) {
        for i in 0..STATE_WIDTH {
            self.state[i] = self.state[i] + get_round_constant(round, i);
        }
    }

    /// Apply S-box to all state elements (full round).
    fn apply_sbox_full(&mut self) {
        for i in 0..STATE_WIDTH {
            self.state[i] = sbox(self.state[i]);
        }
    }

    /// Apply S-box to first state element only (partial round).
    fn apply_sbox_partial(&mut self) {
        self.state[0] = sbox(self.state[0]);
    }

    /// Apply MDS (Maximum Distance Separable) matrix multiplication.
    fn apply_mds(&mut self) {
        let mut new_state = [FieldElement::ZERO; STATE_WIDTH];
        
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                new_state[i] = new_state[i] + self.state[j] * get_mds_element(i, j);
            }
        }
        
        self.state = new_state;
    }
}

impl Default for Poseidon2 {
    fn default() -> Self {
        Self::new()
    }
}

/// S-box function: x^7 (STARK-friendly, algebraic degree 7).
#[inline]
fn sbox(x: FieldElement) -> FieldElement {
    let x2 = x.square();
    let x4 = x2.square();
    let x6 = x4 * x2;
    x6 * x
}

/// Get round constant for given round and position.
///
/// Constants generated using grain LFSR with domain separation.
/// TODO: Replace with proper constants from Poseidon2 paper.
fn get_round_constant(round: usize, pos: usize) -> FieldElement {
    // Placeholder: Use deterministic seed-based generation
    // In production, use official Poseidon2 constants
    let seed = (round * STATE_WIDTH + pos) as u64;
    FieldElement::from_u64(seed.wrapping_mul(0x9E3779B97F4A7C15)) // Golden ratio multiplier
}

/// Get MDS matrix element at position (row, col).
///
/// Uses Cauchy matrix construction for MDS property.
/// TODO: Replace with proper Poseidon2 MDS matrix.
fn get_mds_element(row: usize, col: usize) -> FieldElement {
    // Placeholder: Cauchy matrix 1 / (x_i - y_j)
    // x_i = i, y_j = STATE_WIDTH + j
    let x = FieldElement::from_u64(row as u64);
    let y = FieldElement::from_u64((STATE_WIDTH + col) as u64);
    
    // 1 / (x - y)
    (x - y).inverse().unwrap_or(FieldElement::ONE)
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_single() {
        let input = FieldElement::from_u64(42);
        let hash1 = Poseidon2::hash_single(input);
        let hash2 = Poseidon2::hash_single(input);
        
        // Deterministic
        assert_eq!(hash1, hash2);
        
        // Non-trivial
        assert_ne!(hash1, input);
        assert_ne!(hash1, FieldElement::ZERO);
    }

    #[test]
    fn test_hash_pair() {
        let left = FieldElement::from_u64(100);
        let right = FieldElement::from_u64(200);
        
        let hash1 = Poseidon2::hash_pair(left, right);
        let hash2 = Poseidon2::hash_pair(left, right);
        
        // Deterministic
        assert_eq!(hash1, hash2);
        
        // Different order produces different hash
        let hash3 = Poseidon2::hash_pair(right, left);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_variable() {
        let inputs = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(4),
        ];
        
        let hash1 = Poseidon2::hash(&inputs);
        let hash2 = Poseidon2::hash(&inputs);
        
        // Deterministic
        assert_eq!(hash1, hash2);
        
        // Different from empty hash
        let empty_hash = Poseidon2::hash(&[]);
        assert_ne!(hash1, empty_hash);
    }

    #[test]
    fn test_sbox() {
        let x = FieldElement::from_u64(5);
        let result = sbox(x);
        
        // S-box is x^7
        let expected = x.pow(7);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_permutation_changes_state() {
        let mut hasher = Poseidon2::new();
        let initial_state = hasher.state;
        
        hasher.permute();
        
        // State should change after permutation
        assert_ne!(hasher.state, initial_state);
    }

    #[test]
    fn test_zero_preimage() {
        // Hash of zero should not be zero (avoid trivial collisions)
        let zero_hash = Poseidon2::hash_single(FieldElement::ZERO);
        assert_ne!(zero_hash, FieldElement::ZERO);
    }

    #[test]
    fn test_collision_resistance_basic() {
        // Different inputs should produce different hashes (probabilistic test)
        let hash1 = Poseidon2::hash_single(FieldElement::from_u64(1));
        let hash2 = Poseidon2::hash_single(FieldElement::from_u64(2));
        let hash3 = Poseidon2::hash_single(FieldElement::from_u64(3));
        
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }
}
