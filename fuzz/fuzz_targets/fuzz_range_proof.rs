//! Fuzz target for range proof verification
//!
//! This fuzzer tests the robustness of range proof verification against:
//! - Malformed proof data
//! - Invalid proof lengths
//! - Random byte sequences
//! - Edge case commitments
//!
//! Usage:
//!   cargo fuzz run fuzz_range_proof

#![no_main]

use libfuzzer_sys::fuzz_target;
use crypto::{commit_value, verify_range, Commitment, RangeProof};

fuzz_target!(|data: &[u8]| {
    // We need at least 32 bytes for blinding factor
    if data.len() < 32 {
        return;
    }

    // Split input into blinding factor and proof data
    let (blinding_bytes, proof_data) = data.split_at(32);
    
    // Convert to fixed-size array
    let mut blinding = [0u8; 32];
    blinding.copy_from_slice(blinding_bytes);

    // Strategy 1: Fuzz with valid commitment but random proof data
    let value = u64::from_le_bytes([
        data.get(0).copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
        data.get(6).copied().unwrap_or(0),
        data.get(7).copied().unwrap_or(0),
    ]);

    let commitment = commit_value(value, &blinding);

    // Try to construct a RangeProof from random data
    if let Ok(proof) = RangeProof::new(proof_data.to_vec()) {
        // Verify should not panic, even with invalid data
        let _ = verify_range(&commitment, &proof);
    }

    // Strategy 2: Fuzz commitment bytes directly
    if data.len() >= 64 {
        // 32 bytes for value_commit, 32 bytes for blinding
        let mut value_commit = [0u8; 32];
        value_commit.copy_from_slice(&data[0..32]);
        
        let mut fuzz_blinding = [0u8; 32];
        fuzz_blinding.copy_from_slice(&data[32..64]);

        let fuzzed_commitment = Commitment::new(value_commit, fuzz_blinding);
        let proof_bytes = &data[64..];
        if let Ok(fuzzed_proof) = RangeProof::new(proof_bytes.to_vec()) {
            // Should not panic
            let _ = verify_range(&fuzzed_commitment, &fuzzed_proof);
        }
    }

    // Strategy 3: Test proof size limits
    // MAX_PROOF_SIZE is 32KB - test near boundaries
    if proof_data.len() <= 32 * 1024 {
        let _ = RangeProof::new(proof_data.to_vec());
    }

    // Strategy 4: Test with extreme values
    let extreme_values = [
        0u64,
        1u64,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ];

    for &extreme_value in &extreme_values {
        let extreme_commitment = commit_value(extreme_value, &blinding);
        if let Ok(proof) = RangeProof::new(proof_data.to_vec()) {
            let _ = verify_range(&extreme_commitment, &proof);
        }
    }
});
