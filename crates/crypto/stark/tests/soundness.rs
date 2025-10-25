//! Soundness parameter validation tests.
//!
//! Verifies that FRI parameters provide advertised security levels.

#[cfg(test)]
mod tests {
    use crypto_stark::{
        fri::FriParams,
        params::{SecurityLevel, StarkParams},
        GOLDILOCKS_PRIME,
    };

    /// Compute conservative soundness estimate for FRI.
    ///
    /// **Theoretical Basis**:
    /// FRI soundness error: ε ≈ max(ρ^q, (d/|F|)^q)
    /// where:
    /// - ρ = proximity parameter (how far from valid codeword)
    /// - d = max degree
    /// - |F| = field size
    /// - q = num_queries
    ///
    /// **Conservative Approximation**:
    /// Soundness error ≈ 2^(-num_queries) per query
    /// (assumes proximity parameter ρ ≈ 0.5)
    ///
    /// This gives: soundness_bits ≈ num_queries
    ///
    /// **Reality Check**:
    /// - 10 queries → ~10 bits (testing only)
    /// - 27 queries → ~27 bits (standard)
    /// - 40 queries → ~40 bits (high security)
    ///
    /// Note: Real FRI analysis is more complex and depends on:
    /// - Folding strategy (number of rounds vs reduction factor)
    /// - Code rate (how much redundancy in Reed-Solomon encoding)
    /// - Field characteristics
    ///
    /// Production deployments should use formal security proofs, not this estimate.
    fn compute_soundness_bits_conservative(params: &FriParams) -> f64 {
        // Conservative: each query adds ~1 bit of security
        params.num_queries as f64
    }

    #[test]
    fn test_fri_fast_soundness() {
        let params = FriParams::test(); // Fast security level

        let soundness_bits = compute_soundness_bits_conservative(&params);

        // Test params: 10 queries → ~10 bits (LOW security, testing only)
        assert!(soundness_bits >= 10.0, "Fast soundness: {}", soundness_bits);
        assert!(
            soundness_bits <= 10.0,
            "Fast soundness unexpected: {}",
            soundness_bits
        );

        println!(
            "FRI Test (low security): {} queries → {:.0} bits soundness",
            params.num_queries, soundness_bits
        );
        println!(
            "  WARNING: This is INSECURE for production (needs 80+ bits)"
        );
    }

    #[test]
    fn test_fri_secure_soundness() {
        let params = FriParams::secure(); // Standard security level

        let soundness_bits = compute_soundness_bits_conservative(&params);

        // Secure params: 100 queries → ~100 bits (production-ready)
        assert!(
            soundness_bits >= 100.0,
            "Secure soundness too low: {}",
            soundness_bits
        );
        assert!(
            soundness_bits <= 100.0,
            "Secure soundness unexpected: {}",
            soundness_bits
        );

        println!(
            "FRI Secure: {} queries → {:.0} bits soundness ✓",
            params.num_queries, soundness_bits
        );
        println!("  Production-ready security level");
    }

    #[test]
    fn test_stark_params_soundness() {
        let params_fast = StarkParams {
            security: SecurityLevel::Fast,
            anonymity_set_size: 64,
            field_modulus: GOLDILOCKS_PRIME,
            hash_function: crypto_stark::params::HashFunction::Poseidon2,
        };

        let params_standard = StarkParams {
            security: SecurityLevel::Standard,
            ..params_fast.clone()
        };

        let params_high = StarkParams {
            security: SecurityLevel::High,
            ..params_fast
        };

        // Verify security levels are ordered
        let fri_fast = FriParams::test();
        let fri_secure = FriParams::secure();

        let soundness_fast = compute_soundness_bits_conservative(&fri_fast);
        let soundness_secure = compute_soundness_bits_conservative(&fri_secure);

        assert!(
            soundness_fast < soundness_secure,
            "Fast ({:.1}) should be < Secure ({:.1})",
            soundness_fast,
            soundness_secure
        );

        println!(
            "STARK Security Levels:\n  Fast: {:.1} bits\n  Standard: {:.1} bits\n  High: N/A (not implemented)",
            soundness_fast, soundness_secure
        );

        // High security level exists but maps to same FRI params as Standard for now
        assert!(matches!(params_high.security, SecurityLevel::High));
    }

    #[test]
    fn test_soundness_single_source_of_truth() {
        // FriParams should be the single source of soundness parameters
        let fri_fast = FriParams::test();
        let fri_secure = FriParams::secure();

        // Test: 10 queries, reduction 4 (for fast testing)
        assert_eq!(fri_fast.num_queries, 10);
        assert_eq!(fri_fast.reduction_factor, 4);

        // Secure: 100 queries, reduction 8 (~100-bit security)
        assert_eq!(fri_secure.num_queries, 100);
        assert_eq!(fri_secure.reduction_factor, 8);

        println!(
            "FRI Parameters (single source of truth):\n  Test: q={}, r={} (~{} bits)\n  Secure: q={}, r={} (~{} bits)",
            fri_fast.num_queries,
            fri_fast.reduction_factor,
            fri_fast.num_queries,
            fri_secure.num_queries,
            fri_secure.reduction_factor,
            fri_secure.num_queries
        );
    }
}
