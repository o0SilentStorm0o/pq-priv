use codec::to_vec_cbor;
use consensus::{
    Block, BlockHeader, ChainParams, ConsensusError, next_difficulty, pow_hash, validate_block,
};
use thiserror::Error;
use utxo::{MemoryUtxoStore, OutPoint, UtxoBackend, UtxoError, apply_block};

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("utxo error: {0}")]
    Utxo(#[from] UtxoError),
    #[error("genesis missing transactions")]
    InvalidGenesis,
    #[error("serialization error: {0}")]
    Serialization(#[from] std::io::Error),
    #[error("consensus error: {0}")]
    Consensus(#[from] ConsensusError),
}

pub struct ChainState {
    params: ChainParams,
    blocks: Vec<Block>,
    utxo: MemoryUtxoStore,
}

impl ChainState {
    pub fn bootstrap(params: ChainParams, genesis: Block) -> Result<Self, ChainError> {
        if genesis.txs.is_empty() {
            return Err(ChainError::InvalidGenesis);
        }
        validate_block(None, &genesis, &params)?;
        let mut utxo = MemoryUtxoStore::new();
        apply_block(&mut utxo, &genesis, 0)?;
        Ok(Self {
            params,
            blocks: vec![genesis],
            utxo,
        })
    }

    #[allow(dead_code)]
    pub fn height(&self) -> u64 {
        self.blocks.len().saturating_sub(1) as u64
    }

    #[allow(dead_code)]
    pub fn best_hash(&self) -> [u8; 32] {
        self.blocks
            .last()
            .map(|block| pow_hash(&block.header))
            .unwrap_or([0u8; 32])
    }

    pub fn apply_block(&mut self, block: Block) -> Result<(), ChainError> {
        let height = self.blocks.len() as u64;
        let prev_header = self.blocks.last().map(|blk| &blk.header);
        validate_block(prev_header, &block, &self.params)?;
        if !self.blocks.is_empty() {
            let history = self.recent_headers(self.params.window);
            let expected_bits = next_difficulty(&self.params, &history)?;
            if block.header.n_bits != expected_bits {
                return Err(ChainError::Consensus(ConsensusError::InvalidBits));
            }
            let mtp = self.median_time_past();
            if block.header.time <= mtp {
                return Err(ChainError::Consensus(ConsensusError::InvalidTimestamp));
            }
        }
        apply_block(&mut self.utxo, &block, height)?;
        self.blocks.push(block);
        Ok(())
    }

    pub fn next_difficulty_bits(&self) -> Result<u32, ConsensusError> {
        if self.blocks.is_empty() {
            return Err(ConsensusError::InvalidBits);
        }
        let history = self.recent_headers(self.params.window);
        next_difficulty(&self.params, &history)
    }

    #[allow(dead_code)]
    pub fn has_utxo(&self, txid: &[u8; 32], index: u32) -> bool {
        let outpoint = OutPoint::new(*txid, index);
        self.utxo
            .get(&outpoint)
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn utxo_count(&self) -> usize {
        self.utxo.utxo_count()
    }

    #[allow(dead_code)]
    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.blocks
            .iter()
            .any(|block| pow_hash(&block.header) == *hash)
    }

    #[allow(dead_code)]
    pub fn block_bytes(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.blocks
            .iter()
            .find(|block| pow_hash(&block.header) == *hash)
            .and_then(|block| to_vec_cbor(block).ok())
    }

    pub fn tip(&self) -> &Block {
        self.blocks
            .last()
            .expect("chain must contain at least the genesis block")
    }

    #[allow(dead_code)]
    pub fn block_locator(&self) -> Vec<[u8; 32]> {
        let mut locator = Vec::new();
        if self.blocks.is_empty() {
            return locator;
        }
        let mut step = 1usize;
        let mut index = self.blocks.len() as isize - 1;
        while index >= 0 {
            let hash = pow_hash(&self.blocks[index as usize].header);
            locator.push(hash);
            if index == 0 {
                break;
            }
            index -= step as isize;
            if locator.len() >= 10 {
                step *= 2;
            }
        }
        let genesis_hash = pow_hash(&self.blocks[0].header);
        if locator.last() != Some(&genesis_hash) {
            locator.push(genesis_hash);
        }
        locator
    }

    #[allow(dead_code)]
    pub fn headers_for_locator(
        &self,
        locator: &[[u8; 32]],
        stop: Option<&[u8; 32]>,
        limit: usize,
    ) -> Vec<BlockHeader> {
        let mut start = 0usize;
        for hash in locator {
            if let Some(height) = self.position_of(hash) {
                start = height + 1;
                break;
            }
        }
        let mut headers = Vec::new();
        for block in self.blocks.iter().skip(start) {
            let hash = pow_hash(&block.header);
            if stop.map(|stop_hash| hash == *stop_hash).unwrap_or(false) {
                break;
            }
            headers.push(block.header.clone());
            if headers.len() >= limit {
                break;
            }
        }
        headers
    }

    fn recent_headers(&self, limit: usize) -> Vec<BlockHeader> {
        if self.blocks.is_empty() {
            return Vec::new();
        }
        let len = self.blocks.len();
        let start = len.saturating_sub(limit);
        self.blocks[start..]
            .iter()
            .map(|block| block.header.clone())
            .collect()
    }

    fn position_of(&self, hash: &[u8; 32]) -> Option<usize> {
        self.blocks
            .iter()
            .enumerate()
            .find(|(_, block)| pow_hash(&block.header) == *hash)
            .map(|(idx, _)| idx)
    }

    fn median_time_past(&self) -> u64 {
        let mut times: Vec<u64> = self
            .blocks
            .iter()
            .rev()
            .take(11)
            .map(|block| block.header.time)
            .collect();
        times.sort_unstable();
        times[times.len() / 2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{BlockHeader, ConsensusError, merkle_root};
    use crypto::KeyMaterial;
    use pow::mine_block;
    use tx::{Output, OutputMeta, TxBuilder, Witness, build_stealth_blob};

    #[test]
    fn rejects_block_with_wrong_prev_hash() {
        let params = ChainParams::default();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), genesis.clone()).expect("bootstrap");

        let bogus_prev = [9u8; 32];
        assert_ne!(bogus_prev, pow_hash(&genesis.header));
        let forged = build_block(bogus_prev, 1, &params);

        let err = chain
            .apply_block(forged)
            .expect_err("should reject forged block");
        match err {
            ChainError::Consensus(ConsensusError::InvalidParent) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn block_locator_contains_tip_and_genesis() {
        let params = ChainParams::default();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), genesis).expect("bootstrap");
        for i in 1..=6u64 {
            let block = mine_child_block(&chain, &params, 1_000 + i * params.target_spacing);
            chain.apply_block(block).expect("apply block");
        }
        let locator = chain.block_locator();
        assert_eq!(locator.first(), Some(&pow_hash(&chain.tip().header)));
        assert_eq!(
            locator.last(),
            Some(&pow_hash(&chain.blocks.first().unwrap().header))
        );
    }

    #[test]
    fn headers_for_locator_returns_expected_sequence() {
        let params = ChainParams::default();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), genesis).expect("bootstrap");
        for i in 1..=4u64 {
            let block = mine_child_block(&chain, &params, 1_000 + i * params.target_spacing);
            chain.apply_block(block).expect("apply block");
        }
        let locator = vec![pow_hash(&chain.blocks[2].header)];
        let headers = chain.headers_for_locator(&locator, None, 10);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], chain.blocks[3].header);
        assert_eq!(headers[1], chain.blocks[4].header);
    }

    #[test]
    fn rejects_block_with_wrong_difficulty() {
        let params = ChainParams::default();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), genesis).expect("bootstrap");
        let good = mine_child_block(&chain, &params, 1_000 + params.target_spacing);
        let mut header = good.header.clone();
        let txs = good.txs.clone();
        let bad_bits = header.n_bits.saturating_sub(1);
        header.n_bits = bad_bits;
        let forged = mine_block(header, txs, &params.pow_limit);
        let err = chain.apply_block(forged).expect_err("should reject");
        match err {
            ChainError::Consensus(ConsensusError::InvalidBits) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_block_with_stale_timestamp() {
        let params = ChainParams::default();
        let genesis = build_block([0u8; 32], 0, &params);
        let mut chain = ChainState::bootstrap(params.clone(), genesis).expect("bootstrap");
        let block = mine_child_block(&chain, &params, 1_000 + params.target_spacing);
        chain.apply_block(block).expect("apply block");
        let mut stale = mine_child_block(
            &chain,
            &params,
            chain.tip().header.time, /* same as tip */
        );
        stale.header.time = chain.tip().header.time;
        let err = chain
            .apply_block(stale)
            .expect_err("should reject stale timestamp");
        match err {
            ChainError::Consensus(ConsensusError::InvalidTimestamp) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn build_block(prev_hash: [u8; 32], time: u64, params: &ChainParams) -> Block {
        let tx = coinbase(time);
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: merkle_root(std::slice::from_ref(&tx)),
            utxo_root: [0u8; 32],
            time,
            n_bits: 0x207fffff,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, vec![tx], &params.pow_limit)
    }

    fn coinbase(time: u64) -> tx::Tx {
        let material = KeyMaterial::random();
        let scan = material.derive_scan_keypair(0);
        let spend = material.derive_spend_keypair(0);
        let stealth = build_stealth_blob(&scan.public, &spend.public, &time.to_le_bytes());
        let commitment = crypto::commitment(50, &time.to_le_bytes());
        TxBuilder::new()
            .add_output(Output::new(
                stealth,
                commitment,
                OutputMeta {
                    deposit_flag: false,
                    deposit_id: None,
                },
            ))
            .set_witness(Witness {
                range_proofs: Vec::new(),
                stamp: time,
                extra: Vec::new(),
            })
            .build()
    }

    fn mine_child_block(chain: &ChainState, params: &ChainParams, time: u64) -> Block {
        let tx = coinbase(time);
        let prev_hash = pow_hash(&chain.tip().header);
        let n_bits = chain.next_difficulty_bits().expect("next difficulty");
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: merkle_root(std::slice::from_ref(&tx)),
            utxo_root: [0u8; 32],
            time,
            n_bits,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, vec![tx], &params.pow_limit)
    }
}
