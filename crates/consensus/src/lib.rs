//! Consensus primitives: block structure, PoW target handling and basic validation.

use blake3::Hasher;
use codec::to_vec_cbor;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tx::Tx;

/// Block header as published on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u16,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub utxo_root: [u8; 32],
    pub time: u64,
    pub n_bits: u32,
    pub nonce: u64,
    pub alg_tag: u8,
}

impl BlockHeader {
    /// Serialize the header for hashing.
    pub fn encode(&self) -> Vec<u8> {
        to_vec_cbor(self).expect("encode header")
    }
}

/// Full block including transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

/// Consensus level error codes.
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("insufficient work")]
    InsufficientWork,
    #[error("invalid difficulty bits")]
    InvalidBits,
}

/// Compute the proof-of-work hash for the header.
pub fn pow_hash(header: &BlockHeader) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&header.encode());
    hasher.finalize().into()
}

/// Validate whether a header satisfies its claimed target.
pub fn validate_pow(header: &BlockHeader) -> Result<(), ConsensusError> {
    let target = Target::from_compact(header.n_bits)?;
    let hash = pow_hash(header);
    if is_hash_below_target(&hash, target.as_bytes()) {
        Ok(())
    } else {
        Err(ConsensusError::InsufficientWork)
    }
}

/// Parameters controlling chain behaviour (subset of what will be needed later).
#[derive(Debug, Clone)]
pub struct ChainParams {
    pub target_spacing: u64,
    pub window: usize,
    pub pow_limit: [u8; 32],
}

impl Default for ChainParams {
    fn default() -> Self {
        Self {
            target_spacing: 60,
            window: 60,
            pow_limit: [0xff; 32],
        }
    }
}

/// Difficulty target encoded in compact form (Bitcoin style).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    bytes: [u8; 32],
}

impl Target {
    pub fn from_compact(bits: u32) -> Result<Self, ConsensusError> {
        let exponent = ((bits >> 24) & 0xff) as usize;
        let mantissa = bits & 0x00ff_ffff;
        if exponent == 0 || mantissa == 0 {
            return Err(ConsensusError::InvalidBits);
        }
        let mut value = BigUint::from(mantissa as u64);
        if exponent > 3 {
            let shift = 8 * (exponent - 3);
            value <<= shift;
        } else {
            let shift = 8 * (3 - exponent);
            value >>= shift;
        }
        let bytes = value.to_bytes_be();
        if bytes.len() > 32 {
            return Err(ConsensusError::InvalidBits);
        }
        let mut target = [0u8; 32];
        let start = 32 - bytes.len();
        target[start..].copy_from_slice(&bytes);
        Ok(Self { bytes: target })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

fn is_hash_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for (h, t) in hash.iter().zip(target.iter()) {
        match h.cmp(t) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

/// LWMA difficulty retarget (placeholder, returns previous difficulty when insufficient history).
pub fn next_difficulty(
    _params: &ChainParams,
    last_blocks: &[BlockHeader],
) -> Result<u32, ConsensusError> {
    if last_blocks.is_empty() {
        return Err(ConsensusError::InvalidBits);
    }
    Ok(last_blocks.last().unwrap().n_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_validation_rejects_large_hash() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            utxo_root: [0u8; 32],
            time: 0,
            n_bits: 0x03000001,
            nonce: 0,
            alg_tag: 1,
        };
        assert!(matches!(
            validate_pow(&header),
            Err(ConsensusError::InsufficientWork)
        ));
    }
}
