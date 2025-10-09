//! Consensus primitives: block structure, PoW target handling and basic validation.

use blake3::Hasher;
use codec::to_vec_cbor;
use num_bigint::BigUint;
use num_traits::{One, Zero};
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
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("block contains no transactions")]
    EmptyBlock,
    #[error("merkle root mismatch")]
    InvalidMerkleRoot,
    #[error("previous block hash mismatch")]
    InvalidParent,
}

/// Compute the proof-of-work hash for the header.
pub fn pow_hash(header: &BlockHeader) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&header.encode());
    hasher.finalize().into()
}

/// Validate whether a header satisfies its claimed target.
pub fn validate_pow(header: &BlockHeader, pow_limit: &[u8; 32]) -> Result<(), ConsensusError> {
    let target = Target::from_compact(header.n_bits)?;
    if target.as_bytes() > pow_limit {
        return Err(ConsensusError::InvalidBits);
    }
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
        let pow_limit = Target::from_compact(0x207fffff)
            .expect("valid pow limit")
            .bytes;
        Self {
            target_spacing: 60,
            window: 60,
            pow_limit,
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

    pub fn to_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.bytes)
    }

    pub fn from_biguint(value: &BigUint) -> Self {
        let mut bytes = [0u8; 32];
        let src = value.to_bytes_be();
        let start = 32 - src.len();
        bytes[start..].copy_from_slice(&src);
        Self { bytes }
    }

    pub fn to_compact(&self) -> u32 {
        let bytes = self.bytes;
        let mut exponent = 32;
        while exponent > 0 && bytes[32 - exponent] == 0 {
            exponent -= 1;
        }
        if exponent == 0 {
            return 0;
        }
        let mut mantissa = if exponent >= 3 {
            let start = 32 - exponent;
            ((bytes[start] as u32) << 16)
                | ((bytes[start + 1] as u32) << 8)
                | (bytes[start + 2] as u32)
        } else {
            let mut m = (bytes[31] as u32) << 16;
            if exponent >= 2 {
                m |= (bytes[30] as u32) << 8;
            }
            if exponent >= 1 {
                m |= bytes[29] as u32;
            }
            m
        };
        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8;
            exponent += 1;
        }
        (exponent as u32) << 24 | (mantissa & 0x007f_ffff)
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
    params: &ChainParams,
    last_blocks: &[BlockHeader],
) -> Result<u32, ConsensusError> {
    if last_blocks.is_empty() {
        return Err(ConsensusError::InvalidBits);
    }
    let mut targets = BigUint::zero();
    let mut weighted_time: u128 = 0;
    let count = last_blocks.len().min(params.window);
    let k = (count * (count + 1) / 2) as u128;
    let selected = &last_blocks[last_blocks.len() - count..];
    let mut previous_time = selected
        .first()
        .map(|h| h.time.saturating_sub(params.target_spacing))
        .unwrap_or_default();
    for (i, header) in selected.iter().enumerate() {
        let target = Target::from_compact(header.n_bits)?;
        if target.as_bytes() > &params.pow_limit {
            return Err(ConsensusError::InvalidBits);
        }
        targets += target.to_biguint();
        let mut solvetime = header.time.saturating_sub(previous_time);
        previous_time = header.time;
        if solvetime == 0 {
            solvetime = 1;
        }
        let clamp = params.target_spacing.saturating_mul(6);
        if solvetime > clamp {
            solvetime = clamp;
        }
        let weight = (i + 1) as u128;
        weighted_time += weight * (solvetime as u128);
    }
    let average_target = if count == 0 {
        BigUint::one()
    } else {
        targets / BigUint::from(count as u64)
    };
    let mut lwma = if weighted_time == 0 {
        params.target_spacing as u128
    } else {
        weighted_time / k
    };
    let min_lwma = (params.target_spacing / 4).max(1) as u128;
    if lwma < min_lwma {
        lwma = min_lwma;
    }
    let mut next = average_target * BigUint::from(lwma);
    next /= BigUint::from(params.target_spacing);
    let pow_limit = BigUint::from_bytes_be(&params.pow_limit);
    if next > pow_limit {
        next = pow_limit;
    }
    let next_target = Target::from_biguint(&next);
    Ok(next_target.to_compact())
}

/// Compute the canonical merkle root for the provided transactions.
pub fn merkle_root(txs: &[Tx]) -> [u8; 32] {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            let left = chunk[0];
            let right = chunk.get(1).copied().unwrap_or(left);
            let mut hasher = Hasher::new();
            hasher.update(&left);
            hasher.update(&right);
            next.push(hasher.finalize().into());
        }
        layer = next;
    }
    layer[0]
}

/// Validate a full block against its parent header and chain parameters.
pub fn validate_block(
    prev: Option<&BlockHeader>,
    block: &Block,
    params: &ChainParams,
) -> Result<(), ConsensusError> {
    if block.txs.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }
    if let Some(parent) = prev && block.header.prev_hash != pow_hash(parent) {
        return Err(ConsensusError::InvalidParent);
    }
    validate_pow(&block.header, &params.pow_limit)?;
    let expected_root = merkle_root(&block.txs);
    if expected_root != block.header.merkle_root {
        return Err(ConsensusError::InvalidMerkleRoot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tx::{Output, OutputMeta, TxBuilder, Witness};

    #[test]
    fn pow_validation_rejects_large_hash() {
        let params = ChainParams::default();
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
            validate_pow(&header, &params.pow_limit),
            Err(ConsensusError::InsufficientWork)
        ));
    }

    #[test]
    fn lwma_maintains_target_with_constant_spacing() {
        let params = ChainParams::default();
        let mut headers = Vec::new();
        let mut time = 1_000u64;
        for i in 0..params.window {
            headers.push(BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                utxo_root: [0u8; 32],
                time,
                n_bits: 0x207fffff,
                nonce: i as u64,
                alg_tag: 1,
            });
            time += params.target_spacing;
        }
        let next = next_difficulty(&params, &headers).expect("retarget");
        assert_eq!(next, 0x207fffff);
    }

    #[test]
    fn lwma_eases_difficulty_when_blocks_are_slow() {
        let params = ChainParams::default();
        let mut headers = Vec::new();
        let mut time = 1_000u64;
        for i in 0..params.window {
            headers.push(BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                utxo_root: [0u8; 32],
                time,
                n_bits: 0x207fffff,
                nonce: i as u64,
                alg_tag: 1,
            });
            time += params.target_spacing * 2;
        }
        let next = next_difficulty(&params, &headers).expect("retarget");
        assert!(next > 0x207fffff / 2);
    }

    #[test]
    fn merkle_root_matches_single_txid() {
        let output = Output::new(vec![1, 2, 3], [5u8; 32], OutputMeta::default());
        let tx = TxBuilder::new()
            .add_output(output)
            .set_witness(Witness::default())
            .build();
        assert_eq!(merkle_root(&[tx.clone()]), *tx.txid().as_bytes());
    }
}
