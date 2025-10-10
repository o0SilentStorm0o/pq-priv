use std::sync::Arc;

use codec::{from_slice_cbor, to_vec_cbor};
use rocksdb::{ColumnFamily, DB};
use utxo::{OutPoint, OutputRecord, UtxoBackend, UtxoError};

use crate::schema::{self, META_COMPACT_INDEX};

pub struct RocksUtxoStore {
    db: Arc<DB>,
}

impl RocksUtxoStore {
    pub(crate) fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    fn cf(&self, name: &str) -> Result<&ColumnFamily, UtxoError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| UtxoError::Backend(format!("missing column family {name}")))
    }

    fn db_err(err: rocksdb::Error) -> UtxoError {
        UtxoError::Backend(err.to_string())
    }

    fn codec_err(err: std::io::Error) -> UtxoError {
        UtxoError::Backend(err.to_string())
    }
}

impl UtxoBackend for RocksUtxoStore {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError> {
        let cf = self.cf(schema::CF_UTXO)?;
        let key = schema::utxo_key(&outpoint.txid, outpoint.index);
        let value = match self.db.get_cf(cf, key).map_err(Self::db_err)? {
            Some(raw) => raw,
            None => return Ok(None),
        };
        let record = from_slice_cbor::<OutputRecord>(&value).map_err(Self::codec_err)?;
        Ok(Some(record))
    }

    fn insert(&mut self, outpoint: OutPoint, record: OutputRecord) -> Result<(), UtxoError> {
        let cf = self.cf(schema::CF_UTXO)?;
        let key = schema::utxo_key(&outpoint.txid, outpoint.index);
        let value = to_vec_cbor(&record).map_err(Self::codec_err)?;
        self.db.put_cf(cf, key, value).map_err(Self::db_err)?;
        Ok(())
    }

    fn remove(&mut self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError> {
        let cf = self.cf(schema::CF_UTXO)?;
        let key = schema::utxo_key(&outpoint.txid, outpoint.index);
        let value = match self.db.get_cf(cf, key).map_err(Self::db_err)? {
            Some(raw) => raw,
            None => return Ok(None),
        };
        self.db.delete_cf(cf, key).map_err(Self::db_err)?;
        let record = from_slice_cbor::<OutputRecord>(&value).map_err(Self::codec_err)?;
        Ok(Some(record))
    }

    fn contains_link_tag(&self, tag: &[u8; 32]) -> Result<bool, UtxoError> {
        let cf = self.cf(schema::CF_LINKTAG)?;
        let key = schema::linktag_key(tag);
        let present = self.db.get_cf(cf, key).map_err(Self::db_err)?.is_some();
        Ok(present)
    }

    fn record_link_tag(&mut self, tag: [u8; 32]) -> Result<(), UtxoError> {
        let cf = self.cf(schema::CF_LINKTAG)?;
        let key = schema::linktag_key(&tag);
        self.db.put_cf(cf, key, [1u8]).map_err(Self::db_err)?;
        Ok(())
    }

    fn remove_link_tag(&mut self, tag: &[u8; 32]) -> Result<(), UtxoError> {
        let cf = self.cf(schema::CF_LINKTAG)?;
        let key = schema::linktag_key(tag);
        self.db.delete_cf(cf, key).map_err(Self::db_err)?;
        Ok(())
    }

    fn allocate_compact_index(&mut self) -> Result<u64, UtxoError> {
        let cf_meta = self.cf(schema::CF_META)?;
        let key = schema::meta_key(META_COMPACT_INDEX);
        let current = self
            .db
            .get_cf(cf_meta, &key)
            .map_err(Self::db_err)?
            .map(|raw| schema::decode_height(&raw).map_err(|e| UtxoError::Backend(e.to_string())))
            .transpose()?
            .unwrap_or(0);
        let next = current.saturating_add(1);
        let next_bytes = schema::encode_height(next);
        self.db
            .put_cf(cf_meta, key, next_bytes)
            .map_err(Self::db_err)?;
        Ok(current)
    }
}
