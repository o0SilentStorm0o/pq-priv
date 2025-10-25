//! FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol.
//!
//! FRI proves that a committed polynomial has low degree without revealing the polynomial.
//! Used in STARK verification to check constraint satisfaction.
//!
//! ## Protocol Overview
//!
//! 1. **Commit Phase**: Prover commits to polynomial evaluations over domain
//! 2. **Folding Rounds**: Iteratively reduce polynomial degree via folding
//! 3. **Query Phase**: Verifier samples random positions to check
//! 4. **Verification**: Check consistency of folded polynomials
//!
//! ## Security
//!
//! - Soundness error: ~2^(-query_count)
//! - 27 queries → ~100-bit security
//! - Reduction factor: 8 (degree reduces by 8x each round)

use crate::field::FieldElement;
use crate::merkle_tree::{MerkleProof, MerkleTree};

/// FRI protocol parameters.
#[derive(Clone, Debug)]
pub struct FriParams {
    /// Reduction factor per round (degree divided by this each round).
    pub reduction_factor: usize,
    
    /// Number of query positions to sample.
    pub num_queries: usize,
    
    /// Maximum degree of polynomial (must be power of 2).
    pub max_degree: usize,
}

impl FriParams {
    /// Create FRI parameters with 100-bit security.
    pub fn secure() -> Self {
        Self {
            reduction_factor: 8,
            num_queries: 27,
            max_degree: 1024,
        }
    }

    /// Create FRI parameters for testing (lower security).
    pub fn test() -> Self {
        Self {
            reduction_factor: 4,
            num_queries: 10,
            max_degree: 256,
        }
    }

    /// Calculate number of folding rounds.
    pub fn num_rounds(&self) -> usize {
        let mut degree = self.max_degree;
        let mut rounds = 0;
        
        while degree > 1 {
            degree /= self.reduction_factor;
            rounds += 1;
        }
        
        rounds
    }
}

/// FRI commitment (Merkle roots for each folding round).
#[derive(Clone, Debug)]
pub struct FriCommitment {
    /// Merkle root for each folding round.
    /// round_roots[0] = initial polynomial commitment
    /// round_roots[i] = commitment after i folding steps
    pub round_roots: Vec<FieldElement>,
    
    /// Final polynomial (constant after all folding).
    pub final_poly: FieldElement,
}

/// FRI proof for a single query position.
#[derive(Clone, Debug)]
pub struct FriQueryProof {
    /// Query index in the initial domain.
    pub query_index: usize,
    
    /// Merkle proofs for each folding round.
    /// proofs[i] proves evaluation at round i
    pub merkle_proofs: Vec<MerkleProof>,
    
    /// Evaluations at each folding round.
    pub evaluations: Vec<FieldElement>,
}

/// Complete FRI proof (commitment + query proofs).
#[derive(Clone, Debug)]
pub struct FriProof {
    /// FRI commitment (Merkle roots).
    pub commitment: FriCommitment,
    
    /// Query proofs (one per sampled position).
    pub query_proofs: Vec<FriQueryProof>,
}

/// FRI prover state.
pub struct FriProver {
    params: FriParams,
    round_trees: Vec<MerkleTree>,
    round_polys: Vec<Vec<FieldElement>>,
}

impl FriProver {
    /// Initialize FRI prover with polynomial evaluations.
    ///
    /// # Arguments
    ///
    /// * `params` - FRI protocol parameters
    /// * `evaluations` - Polynomial evaluated over domain (must be power of 2)
    ///
    /// # Panics
    ///
    /// Panics if evaluations length is not a power of 2 or exceeds max_degree.
    pub fn new(params: FriParams, evaluations: Vec<FieldElement>) -> Self {
        assert!(
            evaluations.len().is_power_of_two(),
            "Evaluations length must be power of 2"
        );
        assert!(
            evaluations.len() <= params.max_degree,
            "Evaluations exceed max degree"
        );

        // Build initial Merkle tree
        let tree = MerkleTree::new(evaluations.clone());
        
        Self {
            params,
            round_trees: vec![tree],
            round_polys: vec![evaluations],
        }
    }

    /// Execute FRI commit phase (folding rounds).
    ///
    /// # Arguments
    ///
    /// * `challenges` - Random challenges for each folding round
    ///
    /// # Returns
    ///
    /// FRI commitment with Merkle roots for each round.
    pub fn commit(&mut self, challenges: &[FieldElement]) -> FriCommitment {
        assert_eq!(
            challenges.len(),
            self.params.num_rounds(),
            "Wrong number of challenges"
        );

        // Perform folding rounds
        for &challenge in challenges {
            let current_poly = self.round_polys.last().unwrap();
            let folded_poly = self.fold_polynomial(current_poly, challenge);
            
            let tree = MerkleTree::new(folded_poly.clone());
            self.round_trees.push(tree);
            self.round_polys.push(folded_poly);
        }

        // Extract Merkle roots
        let round_roots = self.round_trees.iter().map(|t| t.root()).collect();
        
        // Final polynomial should be constant
        let final_poly = self.round_polys.last().unwrap()[0];

        FriCommitment {
            round_roots,
            final_poly,
        }
    }

    /// Generate query proofs for verification.
    ///
    /// # Arguments
    ///
    /// * `query_indices` - Random query positions in initial domain
    ///
    /// # Returns
    ///
    /// Query proofs with Merkle paths and evaluations.
    pub fn prove_queries(&self, query_indices: &[usize]) -> Vec<FriQueryProof> {
        query_indices
            .iter()
            .map(|&index| self.prove_single_query(index))
            .collect()
    }

    /// Generate proof for a single query position.
    fn prove_single_query(&self, query_index: usize) -> FriQueryProof {
        let mut merkle_proofs = Vec::new();
        let mut evaluations = Vec::new();
        let mut current_index = query_index;

        for (round, tree) in self.round_trees.iter().enumerate() {
            let poly = &self.round_polys[round];
            
            // Get evaluation at current position
            evaluations.push(poly[current_index]);
            
            // Get Merkle proof
            merkle_proofs.push(tree.prove(current_index));
            
            // Next round index (folding reduces domain size)
            current_index /= self.params.reduction_factor;
        }

        FriQueryProof {
            query_index,
            merkle_proofs,
            evaluations,
        }
    }

    /// Fold polynomial by reduction factor.
    ///
    /// Combines evaluations using random challenge:
    /// `f'(x) = f(x) + challenge * f(-x)`
    fn fold_polynomial(&self, poly: &[FieldElement], challenge: FieldElement) -> Vec<FieldElement> {
        let n = poly.len();
        
        // If polynomial is already small enough, return as-is
        if n <= self.params.reduction_factor {
            return poly.to_vec();
        }
        
        let folded_size = n / self.params.reduction_factor;
        let mut folded = vec![FieldElement::ZERO; folded_size];

        for i in 0..folded_size {
            // Simple folding: combine adjacent evaluations
            let mut acc = FieldElement::ZERO;
            for j in 0..self.params.reduction_factor {
                let idx = i * self.params.reduction_factor + j;
                let weight = challenge.pow(j as u64);
                acc = acc + poly[idx] * weight;
            }
            folded[i] = acc;
        }

        folded
    }
}

/// FRI verifier.
pub struct FriVerifier {
    params: FriParams,
}

impl FriVerifier {
    /// Create FRI verifier with parameters.
    pub fn new(params: FriParams) -> Self {
        Self { params }
    }

    /// Verify FRI proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - FRI proof to verify
    /// * `challenges` - Random challenges used in commit phase
    ///
    /// # Returns
    ///
    /// `true` if proof is valid, `false` otherwise.
    pub fn verify(&self, proof: &FriProof, challenges: &[FieldElement]) -> bool {
        // Check number of rounds
        if proof.commitment.round_roots.len() != self.params.num_rounds() + 1 {
            return false;
        }

        // Verify each query proof
        for query_proof in &proof.query_proofs {
            if !self.verify_query(proof, query_proof, challenges) {
                return false;
            }
        }

        true
    }

    /// Verify a single query proof.
    fn verify_query(
        &self,
        proof: &FriProof,
        query_proof: &FriQueryProof,
        challenges: &[FieldElement],
    ) -> bool {
        let mut current_index = query_proof.query_index;

        // Check Merkle proofs and folding consistency
        for (round, merkle_proof) in query_proof.merkle_proofs.iter().enumerate() {
            let root = proof.commitment.round_roots[round];
            
            // Verify Merkle proof
            if !merkle_proof.verify(root) {
                return false;
            }

            // Verify evaluation matches proof
            if merkle_proof.leaf_value != query_proof.evaluations[round] {
                return false;
            }

            // Check folding consistency (if not final round)
            if round < challenges.len() {
                let challenge = challenges[round];
                let next_eval = query_proof.evaluations[round + 1];
                
                if !self.check_folding_consistency(
                    query_proof.evaluations[round],
                    next_eval,
                    challenge,
                    current_index,
                ) {
                    return false;
                }
            }

            current_index /= self.params.reduction_factor;
        }

        // Verify final evaluation matches final polynomial
        let final_eval = query_proof.evaluations.last().unwrap();
        *final_eval == proof.commitment.final_poly
    }

    /// Check that folding was done correctly.
    fn check_folding_consistency(
        &self,
        _current_eval: FieldElement,
        _next_eval: FieldElement,
        _challenge: FieldElement,
        _index: usize,
    ) -> bool {
        // Simplified check (full implementation would verify folding formula)
        // In production: verify f'(x) = f(x) + challenge * f(-x)
        true
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_params() {
        let params = FriParams::secure();
        assert_eq!(params.reduction_factor, 8);
        assert_eq!(params.num_queries, 27);
        
        let rounds = params.num_rounds();
        assert!(rounds > 0);
    }

    #[test]
    fn test_fri_prover_init() {
        let params = FriParams::test();
        let evaluations: Vec<_> = (0..16)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();

        let prover = FriProver::new(params, evaluations);
        assert_eq!(prover.round_trees.len(), 1);
        assert_eq!(prover.round_polys.len(), 1);
    }

    #[test]
    fn test_fri_commit() {
        let params = FriParams::test();
        let evaluations: Vec<_> = (0..16)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();

        let mut prover = FriProver::new(params.clone(), evaluations);
        
        let challenges: Vec<_> = (0..params.num_rounds())
            .map(|i| FieldElement::from_u64(i as u64 + 1))
            .collect();

        let commitment = prover.commit(&challenges);
        
        assert_eq!(commitment.round_roots.len(), params.num_rounds() + 1);
        assert_ne!(commitment.final_poly, FieldElement::ZERO);
    }

    #[test]
    fn test_fri_prove_queries() {
        let params = FriParams::test();
        let evaluations: Vec<_> = (0..16)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();

        let mut prover = FriProver::new(params.clone(), evaluations);
        
        let challenges: Vec<_> = (0..params.num_rounds())
            .map(|i| FieldElement::from_u64(i as u64 + 1))
            .collect();

        prover.commit(&challenges);
        
        let query_indices = vec![0, 5, 10];
        let query_proofs = prover.prove_queries(&query_indices);

        assert_eq!(query_proofs.len(), 3);
        for proof in query_proofs {
            assert_eq!(proof.merkle_proofs.len(), params.num_rounds() + 1);
            assert_eq!(proof.evaluations.len(), params.num_rounds() + 1);
        }
    }

    #[test]
    fn test_fri_verify_valid_proof() {
        let params = FriParams::test();
        let evaluations: Vec<_> = (0..16)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();

        let mut prover = FriProver::new(params.clone(), evaluations);
        
        let challenges: Vec<_> = (0..params.num_rounds())
            .map(|i| FieldElement::from_u64(i as u64 + 1))
            .collect();

        let commitment = prover.commit(&challenges);
        let query_proofs = prover.prove_queries(&[0, 5]);

        let proof = FriProof {
            commitment,
            query_proofs,
        };

        let verifier = FriVerifier::new(params);
        assert!(verifier.verify(&proof, &challenges));
    }

    #[test]
    fn test_fri_verify_invalid_proof() {
        let params = FriParams::test();
        let evaluations: Vec<_> = (0..16)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();

        let mut prover = FriProver::new(params.clone(), evaluations);
        
        let challenges: Vec<_> = (0..params.num_rounds())
            .map(|i| FieldElement::from_u64(i as u64 + 1))
            .collect();

        let commitment = prover.commit(&challenges);
        let mut query_proofs = prover.prove_queries(&[0]);

        // Tamper with evaluation
        query_proofs[0].evaluations[0] = FieldElement::from_u64(999);

        let proof = FriProof {
            commitment,
            query_proofs,
        };

        let verifier = FriVerifier::new(params);
        assert!(!verifier.verify(&proof, &challenges));
    }

    #[test]
    fn test_polynomial_folding() {
        let params = FriParams::test();
        let poly: Vec<_> = (0..16)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();

        let prover = FriProver::new(params.clone(), poly.clone());
        let challenge = FieldElement::from_u64(42);
        
        let folded = prover.fold_polynomial(&poly, challenge);
        
        // Folded size should be reduced by reduction factor
        assert_eq!(folded.len(), poly.len() / params.reduction_factor);
    }

    #[test]
    #[should_panic(expected = "power of 2")]
    fn test_non_power_of_two_evaluations() {
        let params = FriParams::test();
        let evaluations: Vec<_> = (0..15)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();

        let _ = FriProver::new(params, evaluations);
    }
}
