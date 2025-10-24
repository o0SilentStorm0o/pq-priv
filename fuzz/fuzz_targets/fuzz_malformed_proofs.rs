//! Fuzz target for malformed proof handling
//!
//! This fuzzer specifically targets edge cases in proof parsing and validation:
//! - Empty proofs
//! - Oversized proofs (beyond MAX_PROOF_SIZE)
//! - Proofs with invalid internal structure
//! - Boundary conditions for proof size
//! - Invalid CBOR encoding in proofs
//!
//! Usage:
//!   cargo fuzz run fuzz_malformed_proofs

#![no_main]

use libfuzzer_sys::fuzz_target;
use crypto::{commit_value, prove_range, verify_range, RangeProof, Commitment};

fuzz_target!(|data: &[u8]| {
    // Strategy 1: Test completely random proof data of varying sizes
    let _ = RangeProof::new(data.to_vec());

    // Strategy 2: Test boundary sizes
    let boundary_sizes = [
        0,      // Empty
        1,      // Single byte
        31,     // Just under 32
        32,     // Exactly 32 (minimum valid?)
        64,     // Common small size
        128,
        256,
        512,
        1024,
        8192,
        16384,
        32767,  // MAX_PROOF_SIZE - 1
        32768,  // MAX_PROOF_SIZE (32KB)
        32769,  // MAX_PROOF_SIZE + 1 (should reject)
        65536,  // 64KB (should reject)
    ];

    for &size in &boundary_sizes {
        if data.len() >= size {
            let truncated = &data[..size];
            let _ = RangeProof::new(truncated.to_vec());
        }
    }

    // Strategy 3: Test with valid commitment but malformed proof
    if data.len() >= 32 {
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&data[0..32]);
        
        let value = if data.len() >= 40 {
            u64::from_le_bytes([
                data[32], data[33], data[34], data[35],
                data[36], data[37], data[38], data[39],
            ])
        } else {
            0
        };

        let commitment = commit_value(value, &blinding);

        // Try to verify with malformed proof
        if let Ok(proof) = RangeProof::new(data[32..].to_vec()) {
            let _ = verify_range(&commitment, &proof);
        }
    }

    // Strategy 4: Test proof mutation
    // Create a valid proof, then mutate it
    if data.len() >= 32 {
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&data[0..32]);
        
        let value = 100u64;
        
        if let Ok(valid_proof) = prove_range(value, &blinding) {
            let proof_bytes = valid_proof.as_bytes();
            
            // Mutate various positions in the proof
            for i in 0..proof_bytes.len().min(data.len()) {
                let mut mutated = proof_bytes.to_vec();
                mutated[i] ^= data[i]; // XOR with fuzz data
                
                if let Ok(mutated_proof) = RangeProof::new(mutated) {
                    let commitment = commit_value(value, &blinding);
                    let _ = verify_range(&commitment, &mutated_proof);
                }
            }

            // Truncate valid proof at various positions
            for truncate_at in 0..proof_bytes.len().min(100) {
                let truncated = &proof_bytes[..truncate_at];
                let _ = RangeProof::new(truncated.to_vec());
            }

            // Extend valid proof with garbage
            if data.len() > 100 {
                let mut extended = proof_bytes.to_vec();
                extended.extend_from_slice(&data[..100.min(data.len())]);
                let _ = RangeProof::new(extended);
            }
        }
    }

    // Strategy 5: Test with malformed commitments
    for chunk in data.chunks(64) {
        if chunk.len() == 64 {
            let mut value_commit = [0u8; 32];
            value_commit.copy_from_slice(&chunk[..32]);
            
            let mut blinding = [0u8; 32];
            blinding.copy_from_slice(&chunk[32..]);
            
            let malformed_commitment = Commitment::new(value_commit, blinding);
            // Try to verify with random proof data
            let remaining_data = &data[64.min(data.len())..];
            if let Ok(proof) = RangeProof::new(remaining_data.to_vec()) {
                let _ = verify_range(&malformed_commitment, &proof);
            }
        }
    }

    // Strategy 6: Test repeated patterns
    if data.len() >= 4 {
        let pattern = &data[0..4];
        let mut repeated = Vec::new();
        
        // Repeat pattern to various sizes
        for target_size in [32, 64, 128, 256, 512, 1024, 8192] {
            repeated.clear();
            while repeated.len() < target_size {
                repeated.extend_from_slice(pattern);
            }
            repeated.truncate(target_size);
            
            let _ = RangeProof::new(repeated.clone());
        }
    }

    // Strategy 7: Test all-zero and all-ones edge cases
    let all_zeros = vec![0u8; 1024.min(data.len())];
    let all_ones = vec![0xFFu8; 1024.min(data.len())];
    
    let _ = RangeProof::new(all_zeros);
    let _ = RangeProof::new(all_ones);

    // Strategy 8: Test incremental byte sequences
    if data.len() >= 256 {
        let incremental: Vec<u8> = (0..=255).collect();
        let _ = RangeProof::new(incremental);
    }
});
