//! Fuzz target for confidential transaction validation
//!
//! This fuzzer tests the entire confidential transaction validation pipeline:
//! - Transaction with random confidential outputs
//! - Mismatched proof counts
//! - Invalid commitment/proof combinations
//! - Edge cases in TX structure
//!
//! Usage:
//!   cargo fuzz run fuzz_confidential_tx

#![no_main]

use libfuzzer_sys::fuzz_target;
use crypto::{commit_value, prove_range, RangeProof, Commitment};
use tx::{Output, OutputMeta, Witness, TxBuilder};
use utxo::{MemoryUtxoStore, apply_block};
use consensus::{Block, BlockHeader};

fuzz_target!(|data: &[u8]| {
    // Need substantial data to construct meaningful transactions
    if data.len() < 128 {
        return;
    }

    // Strategy 1: Fuzz output count and proof count mismatch
    let output_count = (data[0] % 10) as usize + 1; // 1-10 outputs
    let proof_count = (data[1] % 10) as usize; // 0-9 proofs (can mismatch!)

    let mut outputs = Vec::new();
    let mut proofs = Vec::new();

    // Generate outputs
    for i in 0..output_count {
        let offset = 2 + i * 40;
        if offset + 40 > data.len() {
            break;
        }

        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&data[offset..offset + 32]);

        let value = u64::from_le_bytes([
            data[offset + 32],
            data[offset + 33],
            data[offset + 34],
            data[offset + 35],
            data[offset + 36],
            data[offset + 37],
            data[offset + 38],
            data[offset + 39],
        ]);

        // Decide if this output should be confidential (based on fuzz data)
        let is_confidential = data[offset] & 0x80 != 0;

        if is_confidential {
            let commitment = commit_value(value, &blinding);
            let output = Output::new_confidential(
                vec![i as u8; 64], // Stealth blob
                commitment,
                OutputMeta::default(),
            );
            outputs.push(output);

            // Try to create proof (might fail for invalid data)
            if let Ok(proof) = prove_range(value, &blinding) {
                proofs.push(proof);
            }
        } else {
            // Transparent output
            let output = Output::new(
                vec![i as u8; 64],
                value,
                OutputMeta::default(),
            );
            outputs.push(output);
        }
    }

    // Strategy 2: Add random proofs (might not match outputs)
    let proof_offset = 2 + output_count * 40;
    for i in 0..proof_count {
        let start = proof_offset + i * 100;
        if start + 100 > data.len() {
            break;
        }

        let proof_data = &data[start..start + 100];
        if let Ok(proof) = RangeProof::new(proof_data.to_vec()) {
            proofs.push(proof);
        }
    }

    // Build transaction
    if !outputs.is_empty() {
        let witness = Witness::new(
            proofs,
            u64::from_le_bytes(data[0..8.min(data.len())].try_into().unwrap_or([0; 8])),
            vec![],
        );

        let mut tx_builder = TxBuilder::new();
        for output in outputs {
            tx_builder = tx_builder.add_output(output);
        }
        let tx = tx_builder.set_witness(witness).build();

        // Strategy 3: Try to apply to UTXO set (should not panic)
        let mut backend = MemoryUtxoStore::new();
        
        // Create minimal block
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            utxo_root: [0u8; 32],
            time: 0,
            n_bits: 0x1d00ffff,
            nonce: 0,
            alg_tag: 0,
        };

        let block = Block {
            header,
            txs: vec![tx],
        };

        // Apply should not panic, even if validation fails
        let _ = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);
    }

    // Strategy 4: Fuzz commitment construction directly
    if data.len() >= 64 {
        for chunk in data.chunks(64) {
            if chunk.len() == 64 {
                let mut value_commit = [0u8; 32];
                value_commit.copy_from_slice(&chunk[..32]);
                
                let mut blinding = [0u8; 32];
                blinding.copy_from_slice(&chunk[32..]);
                
                let commitment = Commitment::new(value_commit, blinding);
                // Create output with potentially invalid commitment
                let output = Output {
                    stealth_blob: vec![0x42; 64],
                    value: data[0] as u64, // Might be non-zero!
                    commitment: Some(commitment),
                    value_commitment: [0u8; 32],
                    output_meta: OutputMeta::default(),
                };

                // Try to use in transaction
                let witness = Witness::default();
                let tx = TxBuilder::new()
                    .add_output(output)
                    .set_witness(witness)
                    .build();

                let header = BlockHeader {
                    version: 1,
                    prev_hash: [0u8; 32],
                    merkle_root: [0u8; 32],
                    utxo_root: [0u8; 32],
                    time: 0,
                    n_bits: 0x1d00ffff,
                    nonce: 0,
                    alg_tag: 0,
                };

                let block = Block {
                    header,
                    txs: vec![tx],
                };

                let mut backend = MemoryUtxoStore::new();
                let _ = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);
            }
        }
    }

    // Strategy 5: Test DoS limits
    // Create transaction with many outputs (up to MAX_PROOFS_PER_BLOCK)
    let max_outputs = (data[0] as usize).min(50); // Cap to avoid OOM in fuzzer
    
    if data.len() >= max_outputs * 32 {
        let mut dos_outputs = Vec::new();
        let mut dos_proofs = Vec::new();

        for i in 0..max_outputs {
            let offset = i * 32;
            let mut blinding = [0u8; 32];
            blinding.copy_from_slice(&data[offset..offset + 32]);

            let commitment = commit_value(i as u64, &blinding);
            let output = Output::new_confidential(
                vec![i as u8; 64],
                commitment,
                OutputMeta::default(),
            );
            dos_outputs.push(output);

            if let Ok(proof) = prove_range(i as u64, &blinding) {
                dos_proofs.push(proof);
            }
        }

        if !dos_outputs.is_empty() {
            let witness = Witness::new(dos_proofs, 0, vec![]);
            let mut tx_builder = TxBuilder::new();
            for output in dos_outputs {
                tx_builder = tx_builder.add_output(output);
            }
            let tx = tx_builder.set_witness(witness).build();

            let header = BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                utxo_root: [0u8; 32],
                time: 0,
                n_bits: 0x1d00ffff,
                nonce: 0,
                alg_tag: 0,
            };

            let block = Block {
                header,
                txs: vec![tx],
            };

            let mut backend = MemoryUtxoStore::new();
            let _ = apply_block(&mut backend, &block, 1, None::<fn(&str, u64)>);
        }
    }
});
