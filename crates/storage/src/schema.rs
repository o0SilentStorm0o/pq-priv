use std::borrow::Cow;

use crate::errors::StorageError;

pub const CF_HEADERS: &str = "HEADERS";
pub const CF_BLOCKS: &str = "BLOCKS";
pub const CF_UTXO: &str = "UTXO";
pub const CF_LINKTAG: &str = "LINKTAG";
pub const CF_META: &str = "META";
pub const CF_NULLIFIERS: &str = "NULLIFIERS";

const PREFIX_HEADER: u8 = b'H';
const PREFIX_BLOCK: u8 = b'B';
const PREFIX_UTXO: u8 = b'U';
const PREFIX_LINKTAG: u8 = b'L';
const PREFIX_META: u8 = b'M';
const PREFIX_NULLIFIER: u8 = b'N';

pub const META_TIP: &str = "tip";
#[allow(dead_code)]
pub const META_POW_LIMIT: &str = "pow_limit";
#[allow(dead_code)]
pub const META_NETWORK: &str = "network";
pub const META_VERSION: &str = "schema_version";
pub const META_COMPACT_INDEX: &str = "compact_index";

#[derive(Copy, Clone, Debug)]
pub enum Column {
    Headers,
    Blocks,
    Utxo,
    LinkTag,
    Meta,
    Nullifiers,
}

impl Column {
    pub const fn name(self) -> &'static str {
        match self {
            Column::Headers => CF_HEADERS,
            Column::Blocks => CF_BLOCKS,
            Column::Utxo => CF_UTXO,
            Column::LinkTag => CF_LINKTAG,
            Column::Meta => CF_META,
            Column::Nullifiers => CF_NULLIFIERS,
        }
    }
}

pub fn header_key(height: u64) -> [u8; 9] {
    let mut buf = [0u8; 9];
    buf[0] = PREFIX_HEADER;
    buf[1..].copy_from_slice(&encode_height(height));
    buf
}

pub fn block_key(hash: &[u8; 32]) -> [u8; 33] {
    let mut buf = [0u8; 33];
    buf[0] = PREFIX_BLOCK;
    buf[1..].copy_from_slice(hash);
    buf
}

pub fn utxo_key(txid: &[u8; 32], index: u32) -> [u8; 37] {
    let mut buf = [0u8; 37];
    buf[0] = PREFIX_UTXO;
    buf[1..33].copy_from_slice(txid);
    buf[33..].copy_from_slice(&index.to_be_bytes());
    buf
}

pub fn linktag_key(tag: &[u8; 32]) -> [u8; 33] {
    let mut buf = [0u8; 33];
    buf[0] = PREFIX_LINKTAG;
    buf[1..].copy_from_slice(tag);
    buf
}

pub fn nullifier_key(nullifier: &[u8; 32]) -> [u8; 33] {
    let mut buf = [0u8; 33];
    buf[0] = PREFIX_NULLIFIER;
    buf[1..].copy_from_slice(nullifier);
    buf
}

pub fn meta_key(name: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + name.len());
    buf.push(PREFIX_META);
    buf.extend_from_slice(name.as_bytes());
    buf
}

pub fn encode_height(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

pub fn decode_height(bytes: &[u8]) -> Result<u64, StorageError> {
    if bytes.len() != 8 {
        return Err(StorageError::Corrupted(Cow::Owned(format!(
            "height wrong length: {}",
            bytes.len()
        ))));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

#[allow(dead_code)]
pub fn decode_hash(bytes: &[u8]) -> Result<[u8; 32], StorageError> {
    if bytes.len() != 32 {
        return Err(StorageError::Corrupted(Cow::Owned(format!(
            "hash wrong length: {}",
            bytes.len()
        ))));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Ok(buf)
}
