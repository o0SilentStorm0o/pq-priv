use std::collections::{HashMap, HashSet};

use codec::{from_slice_cbor, to_vec_cbor};
use consensus::{Block, pow_hash};
use rocksdb::WriteBatch;
use rocksdb::WriteOptions;
use utxo::{OutPoint, OutputRecord, UtxoBackend, UtxoError};

use crate::errors::StorageError;
use crate::schema::{
    self, Column, META_COMPACT_INDEX, META_TIP, block_key, encode_height, header_key, linktag_key,
    meta_key,
};
use crate::store::{Store, TipInfo, TipMetadata};

#[derive(Clone)]
enum UtxoOverlay {
    Insert(OutputRecord),
    Delete,
}

pub struct BlockBatch {
    store: Store,
    writes: WriteBatch,
    utxos: HashMap<OutPoint, UtxoOverlay>,
    link_tags: HashSet<[u8; 32]>,
    cleared_tags: HashSet<[u8; 32]>,
    compact_next: u64,
    compact_dirty: bool,
}

pub struct BatchUtxoBackend<'a> {
    batch: &'a mut BlockBatch,
}

impl BlockBatch {
    pub fn new(store: Store) -> Result<Self, StorageError> {
        let compact_next = store.compact_index()?;
        Ok(Self {
            store,
            writes: WriteBatch::default(),
            utxos: HashMap::new(),
            link_tags: HashSet::new(),
            cleared_tags: HashSet::new(),
            compact_next,
            compact_dirty: false,
        })
    }

    pub fn utxo_backend(&mut self) -> BatchUtxoBackend<'_> {
        BatchUtxoBackend { batch: self }
    }

    pub fn stage_block(&mut self, height: u64, block: &Block) -> Result<(), StorageError> {
        let header_bytes = to_vec_cbor(&block.header)?;
        let block_bytes = to_vec_cbor(block)?;
        let cf_headers = self.store.cf(Column::Headers)?;
        let cf_blocks = self.store.cf(Column::Blocks)?;
        self.writes
            .put_cf(&cf_headers, header_key(height), header_bytes);
        let hash = pow_hash(&block.header);
        self.writes
            .put_cf(&cf_blocks, block_key(&hash), block_bytes);
        Ok(())
    }

    pub fn stage_tip(&mut self, tip: &TipInfo) -> Result<(), StorageError> {
        let cf_meta = self.store.cf(Column::Meta)?;
        let meta = TipMetadata::from_info(tip);
        let bytes = serde_json::to_vec(&meta)?;
        self.writes.put_cf(&cf_meta, meta_key(META_TIP), bytes);
        Ok(())
    }

    pub fn commit(mut self) -> Result<(), StorageError> {
        if self.compact_dirty {
            let cf_meta = self.store.cf(Column::Meta)?;
            let bytes = encode_height(self.compact_next);
            self.writes
                .put_cf(&cf_meta, meta_key(META_COMPACT_INDEX), bytes);
        }
        let mut opts = WriteOptions::default();
        opts.disable_wal(false);

        // Measure write batch latency for metrics
        #[cfg(feature = "metrics")]
        let _timer = crate::metrics::WriteBatchTimer::start();

        self.store.db().write_opt(self.writes, &opts)?;
        Ok(())
    }

    fn read_utxo(&self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, StorageError> {
        if let Some(entry) = self.utxos.get(outpoint) {
            match entry {
                UtxoOverlay::Insert(record) => return Ok(Some(record.clone())),
                UtxoOverlay::Delete => return Ok(None),
            }
        }
        let cf = self.store.cf(Column::Utxo)?;
        let key = schema::utxo_key(&outpoint.txid, outpoint.index);
        let value = match self.store.db().get_cf(&cf, key)? {
            Some(raw) => raw,
            None => return Ok(None),
        };
        let record = from_slice_cbor::<OutputRecord>(&value)?;
        Ok(Some(record))
    }

    fn insert_utxo(
        &mut self,
        outpoint: OutPoint,
        record: OutputRecord,
    ) -> Result<(), StorageError> {
        let cf = self.store.cf(Column::Utxo)?;
        let key = schema::utxo_key(&outpoint.txid, outpoint.index);
        let bytes = to_vec_cbor(&record)?;
        self.writes.put_cf(&cf, key, bytes);
        self.utxos.insert(outpoint, UtxoOverlay::Insert(record));
        Ok(())
    }

    fn remove_utxo(&mut self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, StorageError> {
        if let Some(entry) = self.utxos.get_mut(outpoint) {
            match entry {
                UtxoOverlay::Insert(record) => {
                    let cloned = record.clone();
                    *entry = UtxoOverlay::Delete;
                    let cf = self.store.cf(Column::Utxo)?;
                    let key = schema::utxo_key(&outpoint.txid, outpoint.index);
                    self.writes.delete_cf(&cf, key);
                    return Ok(Some(cloned));
                }
                UtxoOverlay::Delete => return Ok(None),
            }
        }
        let record = self.read_utxo(outpoint)?;
        if record.is_some() {
            let cf = self.store.cf(Column::Utxo)?;
            let key = schema::utxo_key(&outpoint.txid, outpoint.index);
            self.writes.delete_cf(&cf, key);
            self.utxos.insert(*outpoint, UtxoOverlay::Delete);
        }
        Ok(record)
    }

    fn contains_link_tag(&self, tag: &[u8; 32]) -> Result<bool, StorageError> {
        if self.link_tags.contains(tag) {
            return Ok(true);
        }
        if self.cleared_tags.contains(tag) {
            return Ok(false);
        }
        let cf = self.store.cf(Column::LinkTag)?;
        let key = linktag_key(tag);
        let present = self.store.db().get_cf(&cf, key)?.is_some();
        Ok(present)
    }

    fn record_link_tag(&mut self, tag: [u8; 32]) -> Result<(), StorageError> {
        if self.link_tags.insert(tag) {
            self.cleared_tags.remove(&tag);
            let cf = self.store.cf(Column::LinkTag)?;
            self.writes.put_cf(&cf, linktag_key(&tag), [1u8]);
        }
        Ok(())
    }

    fn remove_link_tag(&mut self, tag: &[u8; 32]) -> Result<(), StorageError> {
        self.link_tags.remove(tag);
        self.cleared_tags.insert(*tag);
        let cf = self.store.cf(Column::LinkTag)?;
        self.writes.delete_cf(&cf, linktag_key(tag));
        Ok(())
    }
}

impl<'a> UtxoBackend for BatchUtxoBackend<'a> {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError> {
        self.batch
            .read_utxo(outpoint)
            .map_err(|err| UtxoError::Backend(err.to_string()))
    }

    fn insert(&mut self, outpoint: OutPoint, record: OutputRecord) -> Result<(), UtxoError> {
        self.batch
            .insert_utxo(outpoint, record)
            .map_err(|err| UtxoError::Backend(err.to_string()))
    }

    fn remove(&mut self, outpoint: &OutPoint) -> Result<Option<OutputRecord>, UtxoError> {
        self.batch
            .remove_utxo(outpoint)
            .map_err(|err| UtxoError::Backend(err.to_string()))
    }

    fn contains_link_tag(&self, tag: &[u8; 32]) -> Result<bool, UtxoError> {
        self.batch
            .contains_link_tag(tag)
            .map_err(|err| UtxoError::Backend(err.to_string()))
    }

    fn record_link_tag(&mut self, tag: [u8; 32]) -> Result<(), UtxoError> {
        self.batch
            .record_link_tag(tag)
            .map_err(|err| UtxoError::Backend(err.to_string()))
    }

    fn remove_link_tag(&mut self, tag: &[u8; 32]) -> Result<(), UtxoError> {
        self.batch
            .remove_link_tag(tag)
            .map_err(|err| UtxoError::Backend(err.to_string()))
    }

    fn allocate_compact_index(&mut self) -> Result<u64, UtxoError> {
        let index = self.batch.compact_next;
        self.batch.compact_next = self.batch.compact_next.saturating_add(1);
        self.batch.compact_dirty = true;
        Ok(index)
    }
}
