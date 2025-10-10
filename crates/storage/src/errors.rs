use std::borrow::Cow;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("rocksdb error: {0}")]
    Db(#[from] rocksdb::Error),
    #[error("serialization error: {0}")]
    Codec(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("missing column family: {0}")]
    MissingColumn(&'static str),
    #[error("missing metadata entry: {0}")]
    MissingMeta(&'static str),
    #[error("corrupted data: {0}")]
    Corrupted(Cow<'static, str>),
}
