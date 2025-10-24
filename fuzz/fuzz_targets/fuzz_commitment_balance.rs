//! Fuzz target for commitment balance verification
//!
//! This fuzzer tests the robustness of balance_commitments() against:
//! - Random commitment combinations
//! - Varying input/output counts
//! - Edge case commitment values
//! - Potential overflow/underflow scenarios
//!
//! Usage:
//!   cargo fuzz run fuzz_commitment_balance

#![no_main]

use libfuzzer_sys::fuzz_target;
use crypto::{commit_value, balance_commitments, Commitment};

fuzz_target!(|data: &[u8]| {
    // We need at least enough data to create commitments
    if data.len() < 64 {
        return;
    }

    // Strategy 1: Generate multiple random commitments and test balance
    let chunk_size = 40; // 32 bytes blinding + 8 bytes value
    let num_chunks = data.len() / chunk_size;

    if num_chunks < 2 {
        return;
    }

    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    for i in 0..num_chunks {
        let offset = i * chunk_size;
        if offset + chunk_size > data.len() {
            break;
        }

        let chunk = &data[offset..offset + chunk_size];
        
        // Extract blinding (32 bytes) and value (8 bytes)
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&chunk[0..32]);
        
        let value = u64::from_le_bytes([
            chunk[32], chunk[33], chunk[34], chunk[35],
            chunk[36], chunk[37], chunk[38], chunk[39],
        ]);

        let commitment = commit_value(value, &blinding);

        // Split commitments into inputs and outputs
        if i % 2 == 0 {
            inputs.push(commitment);
        } else {
            outputs.push(commitment);
        }
    }

    // Test balance with random split
    if !inputs.is_empty() && !outputs.is_empty() {
        let _ = balance_commitments(&inputs, &outputs);
    }

    // Strategy 2: Test with empty inputs/outputs
    if !inputs.is_empty() {
        let _ = balance_commitments(&inputs, &[]);
        let _ = balance_commitments(&[], &inputs);
    }

    // Strategy 3: Test with same commitment on both sides
    if !inputs.is_empty() {
        let same_commitment = inputs[0].clone();
        let _ = balance_commitments(&[same_commitment.clone()], &[same_commitment]);
    }

    // Strategy 4: Test with raw commitment bytes
    let mut raw_inputs = Vec::new();
    let mut raw_outputs = Vec::new();

    for chunk in data.chunks(64) {
        if chunk.len() == 64 {
            let mut value_commit = [0u8; 32];
            value_commit.copy_from_slice(&chunk[..32]);
            
            let mut blinding = [0u8; 32];
            blinding.copy_from_slice(&chunk[32..]);
            
            let commitment = Commitment::new(value_commit, blinding);
            if raw_inputs.len() < 5 {
                raw_inputs.push(commitment);
            } else if raw_outputs.len() < 5 {
                raw_outputs.push(commitment);
            } else {
                break;
            }
        }
    }

    if !raw_inputs.is_empty() && !raw_outputs.is_empty() {
        let _ = balance_commitments(&raw_inputs, &raw_outputs);
    }

    // Strategy 5: Test with extreme counts
    // Limit to reasonable size to avoid OOM
    const MAX_COMMITMENTS: usize = 100;
    
    if inputs.len() > MAX_COMMITMENTS {
        inputs.truncate(MAX_COMMITMENTS);
    }
    if outputs.len() > MAX_COMMITMENTS {
        outputs.truncate(MAX_COMMITMENTS);
    }

    if !inputs.is_empty() || !outputs.is_empty() {
        let _ = balance_commitments(&inputs, &outputs);
    }

    // Strategy 6: Test mathematical edge cases
    // Create commitments with values that might overflow
    if data.len() >= 96 {
        let mut blinding1 = [0u8; 32];
        let mut blinding2 = [0u8; 32];
        let mut blinding3 = [0u8; 32];
        
        blinding1.copy_from_slice(&data[0..32]);
        blinding2.copy_from_slice(&data[32..64]);
        blinding3.copy_from_slice(&data[64..96]);

        let c1 = commit_value(u64::MAX, &blinding1);
        let c2 = commit_value(u64::MAX / 2, &blinding2);
        let c3 = commit_value(u64::MAX / 2, &blinding3);

        // Test various combinations
        let _ = balance_commitments(&[c1.clone()], &[c2.clone(), c3.clone()]);
        let _ = balance_commitments(&[c1.clone(), c2.clone()], &[c3.clone()]);
        let _ = balance_commitments(&[c1], &[c2, c3]);
    }
});
