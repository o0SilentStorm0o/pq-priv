use codec::to_vec_cbor;
use consensus::{Block, ChainParams, pow_hash};
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
        let mut utxo = MemoryUtxoStore::new();
        apply_block(&mut utxo, &genesis, 0)?;
        Ok(Self {
            params,
            blocks: vec![genesis],
            utxo,
        })
    }

    pub fn height(&self) -> u64 {
        self.blocks.len().saturating_sub(1) as u64
    }

    pub fn best_hash(&self) -> [u8; 32] {
        self.blocks
            .last()
            .map(|block| pow_hash(&block.header))
            .unwrap_or([0u8; 32])
    }

    pub fn apply_block(&mut self, block: Block) -> Result<(), ChainError> {
        let height = (self.blocks.len()) as u64;
        apply_block(&mut self.utxo, &block, height)?;
        self.blocks.push(block);
        Ok(())
    }

    pub fn has_utxo(&self, txid: &[u8; 32], index: u32) -> bool {
        let outpoint = OutPoint::new(*txid, index);
        self.utxo
            .get(&outpoint)
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.blocks
            .iter()
            .any(|block| pow_hash(&block.header) == *hash)
    }

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
}
