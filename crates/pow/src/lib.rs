//! Simple CPU bound proof-of-work search utilities.

use consensus::{Block, BlockHeader, ConsensusError, validate_pow};
use rand::RngCore;
use tx::Tx;

/// Incrementally bump the nonce until a valid solution is found.
pub fn mine_block(mut header: BlockHeader, txs: Vec<Tx>, pow_limit: &[u8; 32]) -> Block {
    loop {
        if validate_pow(&header, pow_limit).is_ok() {
            return Block { header, txs };
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
}

/// Try a batch of random nonces; return the successful header if any.
pub fn search_random_nonce(
    header: &BlockHeader,
    attempts: u64,
    pow_limit: &[u8; 32],
) -> Result<BlockHeader, ConsensusError> {
    let mut header = header.clone();
    let mut rng = rand::thread_rng();
    for _ in 0..attempts {
        header.nonce = rng.next_u64();
        if validate_pow(&header, pow_limit).is_ok() {
            return Ok(header);
        }
    }
    Err(ConsensusError::InsufficientWork)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{ChainParams, pow_hash};

    #[test]
    fn pow_hash_changes_with_nonce() {
        let mut header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            utxo_root: [0u8; 32],
            time: 0,
            n_bits: 0x207fffff,
            nonce: 0,
            alg_tag: 1,
        };
        let hash1 = pow_hash(&header);
        header.nonce = 42;
        let hash2 = pow_hash(&header);
        assert_ne!(hash1, hash2);

        let params = ChainParams::default();
        let mined = mine_block(header, Vec::new(), &params.pow_limit);
        assert!(validate_pow(&mined.header, &params.pow_limit).is_ok());
    }
}
