use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;

use ::num_bigint::BigUint;
use ::num_traits::{Num, Zero};
use codec::from_slice_cbor;
use consensus::{Block, BlockHeader, block_work, pow_hash};
use rocksdb::checkpoint::Checkpoint;
use rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DB, DBCompressionType,
    IteratorMode, Options, WriteBatch, WriteOptions,
};
use serde::{Deserialize, Serialize};

use crate::batch::BlockBatch;
use crate::config::DbTuning;
use crate::errors::StorageError;
use crate::schema::{
    self, Column, META_COMPACT_INDEX, META_TIP, block_key, decode_height, encode_height,
    header_key, meta_key,
};
use crate::utxo_store::RocksUtxoStore;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct TipInfo {
    pub height: u64,
    pub hash: [u8; 32],
    pub cumulative_work: BigUint,
    pub reorg_count: u64,
}

impl TipInfo {
    pub fn new(height: u64, hash: [u8; 32], cumulative_work: BigUint, reorg_count: u64) -> Self {
        Self {
            height,
            hash,
            cumulative_work,
            reorg_count,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TipMetadata {
    height: u64,
    hash: [u8; 32],
    work: String,
    reorg_count: u64,
}

impl TipMetadata {
    pub(crate) fn from_info(info: &TipInfo) -> Self {
        Self {
            height: info.height,
            hash: info.hash,
            work: info.cumulative_work.to_str_radix(16),
            reorg_count: info.reorg_count,
        }
    }

    pub(crate) fn into_info(self) -> Result<TipInfo, StorageError> {
        let work = BigUint::from_str_radix(&self.work, 16).map_err(|_| {
            StorageError::Corrupted(Cow::Owned(format!(
                "invalid cumulative work encoding: {}",
                self.work
            )))
        })?;
        Ok(TipInfo::new(self.height, self.hash, work, self.reorg_count))
    }
}

#[derive(Clone)]
pub struct Store {
    db: Arc<DB>,
    /// Block cache must be kept alive for the lifetime of the DB
    #[allow(dead_code)]
    block_cache: Option<Arc<Cache>>,
}

impl Store {
    /// Build RocksDB options from tuning configuration.
    fn build_db_options(tuning: &DbTuning) -> (Options, BlockBasedOptions, Option<Arc<Cache>>) {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Parallelism
        opts.increase_parallelism(tuning.max_background_jobs());

        // Compaction
        opts.set_level_compaction_dynamic_level_bytes(tuning.compaction_dynamic());
        opts.set_target_file_size_base(tuning.target_file_size_mb() * 1024 * 1024);

        // Write buffer
        opts.set_write_buffer_size((tuning.write_buffer_mb() as usize) * 1024 * 1024);

        // Sync settings
        opts.set_bytes_per_sync(tuning.bytes_per_sync_mb() * 1024 * 1024);
        opts.set_wal_bytes_per_sync(tuning.wal_bytes_per_sync_mb() * 1024 * 1024);

        // Compression
        match tuning.compression() {
            "lz4" => opts.set_compression_type(DBCompressionType::Lz4),
            "zstd" => opts.set_compression_type(DBCompressionType::Zstd),
            "none" => opts.set_compression_type(DBCompressionType::None),
            _ => opts.set_compression_type(DBCompressionType::Zstd),
        }

        // Pipelined writes
        if tuning.enable_pipelined_write() {
            opts.set_enable_pipelined_write(true);
        }

        // Read-ahead
        if tuning.readahead_mb() > 0 {
            opts.set_advise_random_on_open(false);
            opts.set_allow_concurrent_memtable_write(true);
            opts.set_compaction_readahead_size((tuning.readahead_mb() * 1024 * 1024) as usize);
        }

        // Block-based table options
        let mut block_opts = BlockBasedOptions::default();
        let cache = if tuning.block_cache_mb() > 0 {
            let cache = Arc::new(Cache::new_lru_cache(
                (tuning.block_cache_mb() as usize) * 1024 * 1024,
            ));
            block_opts.set_block_cache(&cache);
            Some(cache)
        } else {
            None
        };
        block_opts.set_bloom_filter(10.0, false);

        (opts, block_opts, cache)
    }

    /// Open database with default tuning.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let tuning = DbTuning::default().from_env();
        Self::open_with_tuning(path, tuning)
    }

    /// Open database with custom tuning parameters.
    pub fn open_with_tuning(
        path: impl AsRef<Path>,
        tuning: DbTuning,
    ) -> Result<Self, StorageError> {
        let (mut opts, block_opts, cache) = Self::build_db_options(&tuning);

        opts.set_block_based_table_factory(&block_opts);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(schema::CF_HEADERS, opts.clone()),
            ColumnFamilyDescriptor::new(schema::CF_BLOCKS, opts.clone()),
            ColumnFamilyDescriptor::new(schema::CF_UTXO, opts.clone()),
            ColumnFamilyDescriptor::new(schema::CF_LINKTAG, opts.clone()),
            ColumnFamilyDescriptor::new(schema::CF_META, opts.clone()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;
        let store = Self {
            db: Arc::new(db),
            block_cache: cache,
        };
        store.ensure_bootstrap()?;
        Ok(store)
    }

    pub fn begin_block_batch(&self) -> Result<BlockBatch, StorageError> {
        BlockBatch::new(self.clone())
    }

    pub fn new_utxo_store(&self) -> RocksUtxoStore {
        RocksUtxoStore::new(self.db.clone())
    }

    pub fn tip(&self) -> Result<Option<TipInfo>, StorageError> {
        let cf_meta = self.cf(Column::Meta)?;
        let key = meta_key(META_TIP);
        let data = match self.db.get_cf(&cf_meta, &key)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let meta: TipMetadata = serde_json::from_slice(&data)?;
        Ok(Some(meta.into_info()?))
    }

    pub fn set_tip_meta(&self, tip: &TipInfo) -> Result<(), StorageError> {
        let cf_meta = self.cf(Column::Meta)?;
        let key = meta_key(META_TIP);
        let meta = TipMetadata::from_info(tip);
        let data = serde_json::to_vec(&meta)?;
        let mut opts = WriteOptions::default();
        opts.disable_wal(false);
        self.db.put_cf_opt(&cf_meta, &key, data, &opts)?;
        Ok(())
    }

    pub fn clear_tip_meta(&self) -> Result<(), StorageError> {
        let cf_meta = self.cf(Column::Meta)?;
        let key = meta_key(META_TIP);
        let mut opts = WriteOptions::default();
        opts.disable_wal(false);
        self.db.delete_cf_opt(&cf_meta, &key, &opts)?;
        Ok(())
    }

    pub fn header_by_height(&self, height: u64) -> Result<Option<BlockHeader>, StorageError> {
        let cf = self.cf(Column::Headers)?;
        let key = header_key(height);
        let value = match self.db.get_cf(&cf, key)? {
            Some(data) => data,
            None => return Ok(None),
        };
        let header = from_slice_cbor::<BlockHeader>(&value)?;
        Ok(Some(header))
    }

    pub fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Block>, StorageError> {
        let cf = self.cf(Column::Blocks)?;
        let key = block_key(hash);
        let value = match self.db.get_cf(&cf, key)? {
            Some(data) => data,
            None => return Ok(None),
        };
        let block = from_slice_cbor::<Block>(&value)?;
        Ok(Some(block))
    }

    pub fn block_by_height(&self, height: u64) -> Result<Option<Block>, StorageError> {
        let header = match self.header_by_height(height)? {
            Some(header) => header,
            None => return Ok(None),
        };
        let hash = pow_hash(&header);
        self.block_by_hash(&hash)
    }

    pub fn load_blocks(&self) -> Result<Vec<Block>, StorageError> {
        let cf_headers = self.cf(Column::Headers)?;
        let iter = self.db.iterator_cf(&cf_headers, IteratorMode::Start);
        let mut blocks = Vec::new();
        for entry in iter {
            let (key, value) = entry?;
            if key.is_empty() {
                continue;
            }
            let height = decode_height(&key[1..])?; // strip prefix
            let header = from_slice_cbor::<BlockHeader>(&value)?;
            let hash = pow_hash(&header);
            let block = self.block_by_hash(&hash)?.ok_or_else(|| {
                StorageError::Corrupted(Cow::Owned(format!(
                    "missing block body for height {height}"
                )))
            })?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    pub fn utxo_len(&self) -> Result<usize, StorageError> {
        let cf = self.cf(Column::Utxo)?;
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut count = 0usize;
        for entry in iter {
            entry?;
            count += 1;
        }
        Ok(count)
    }

    pub fn reset_utxo(&self) -> Result<(), StorageError> {
        self.clear_cf(Column::Utxo)?;
        self.clear_cf(Column::LinkTag)?;
        self.set_compact_index(0)?;
        Ok(())
    }

    pub fn rewind_to(&self, height: u64) -> Result<(), StorageError> {
        let tip = match self.tip()? {
            Some(tip) => tip,
            None => return Ok(()),
        };
        if height >= tip.height {
            return Ok(());
        }
        let cf_headers = self.cf(Column::Headers)?;
        let cf_blocks = self.cf(Column::Blocks)?;
        let mut batch = WriteBatch::default();
        for h in (height + 1)..=tip.height {
            batch.delete_cf(&cf_headers, header_key(h));
            if let Some(header) = self.header_by_height(h)? {
                let hash = pow_hash(&header);
                batch.delete_cf(&cf_blocks, block_key(&hash));
            }
        }
        let mut opts = WriteOptions::default();
        opts.disable_wal(false);
        self.db.write_opt(batch, &opts)?;
        if let Some(block) = self.block_by_height(height)? {
            let hash = pow_hash(&block.header);
            let work = self.cumulative_work_to_height(height)?;
            let next_tip = TipInfo::new(height, hash, work, tip.reorg_count);
            self.set_tip_meta(&next_tip)?;
        } else {
            self.clear_tip_meta()?;
        }
        Ok(())
    }

    pub fn set_compact_index(&self, value: u64) -> Result<(), StorageError> {
        let cf_meta = self.cf(Column::Meta)?;
        let key = meta_key(META_COMPACT_INDEX);
        let bytes = encode_height(value);
        let mut opts = WriteOptions::default();
        opts.disable_wal(false);
        self.db.put_cf_opt(&cf_meta, &key, bytes, &opts)?;
        Ok(())
    }

    pub fn clear_compact_index(&self) -> Result<(), StorageError> {
        let cf_meta = self.cf(Column::Meta)?;
        let key = meta_key(META_COMPACT_INDEX);
        let mut opts = WriteOptions::default();
        opts.disable_wal(false);
        self.db.delete_cf_opt(&cf_meta, &key, &opts)?;
        Ok(())
    }

    pub fn compact_index(&self) -> Result<u64, StorageError> {
        let cf_meta = self.cf(Column::Meta)?;
        let key = meta_key(META_COMPACT_INDEX);
        let raw = self
            .db
            .get_cf(&cf_meta, &key)?
            .unwrap_or_else(|| encode_height(0).to_vec());
        decode_height(&raw)
    }

    pub fn create_checkpoint(&self, path: impl AsRef<Path>) -> Result<(), StorageError> {
        let checkpoint = Checkpoint::new(&self.db)?;
        checkpoint.create_checkpoint(path)?;
        Ok(())
    }

    pub fn running_compactions(&self) -> Result<u64, StorageError> {
        Ok(self
            .db
            .property_int_value("rocksdb.num-running-compactions")?
            .unwrap_or(0))
    }

    /// Returns the approximate total size of all SST files in bytes.
    /// This includes all column families and live data on disk.
    pub fn total_db_size(&self) -> Result<u64, StorageError> {
        Ok(self
            .db
            .property_int_value("rocksdb.total-sst-files-size")?
            .unwrap_or(0))
    }

    pub(crate) fn db(&self) -> Arc<DB> {
        self.db.clone()
    }

    pub(crate) fn cf(&self, column: Column) -> Result<Arc<BoundColumnFamily<'_>>, StorageError> {
        self.db
            .cf_handle(column.name())
            .ok_or(StorageError::MissingColumn(column.name()))
    }

    fn ensure_bootstrap(&self) -> Result<(), StorageError> {
        let cf_meta = self.cf(Column::Meta)?;
        let version_key = meta_key(schema::META_VERSION);
        if self.db.get_cf(&cf_meta, &version_key)?.is_none() {
            let mut opts = WriteOptions::default();
            opts.disable_wal(false);
            self.db
                .put_cf_opt(&cf_meta, &version_key, SCHEMA_VERSION.to_be_bytes(), &opts)?;
        }
        let compact_key = meta_key(META_COMPACT_INDEX);
        if self.db.get_cf(&cf_meta, &compact_key)?.is_none() {
            self.set_compact_index(0)?;
        }
        Ok(())
    }

    fn clear_cf(&self, column: Column) -> Result<(), StorageError> {
        let cf = self.cf(column)?;
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut batch = WriteBatch::default();
        for entry in iter {
            let (key, _) = entry?;
            batch.delete_cf(&cf, key);
        }
        let mut opts = WriteOptions::default();
        opts.disable_wal(false);
        self.db.write_opt(batch, &opts)?;
        Ok(())
    }

    fn cumulative_work_to_height(&self, height: u64) -> Result<BigUint, StorageError> {
        let mut work = BigUint::zero();
        for h in 0..=height {
            let header = self.header_by_height(h)?.ok_or_else(|| {
                StorageError::Corrupted(Cow::Owned(format!("missing header at height {h}")))
            })?;
            let block_work = block_work(header.n_bits).map_err(|err| {
                StorageError::Corrupted(Cow::Owned(format!(
                    "failed to compute work at height {h}: {err}"
                )))
            })?;
            work += block_work;
        }
        Ok(work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{ChainParams, merkle_root};
    use crypto::KeyMaterial;
    use pow::mine_block;
    use tempfile::tempdir;
    use tx::{Output, OutputMeta, TxBuilder, Witness, build_stealth_blob};
    use utxo::{UtxoBackend, apply_block};

    #[test]
    fn block_batch_commits_header_and_tip() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let params = ChainParams::default();
        let genesis = build_block([0u8; 32], 1, &params);
        let mut batch = store.begin_block_batch().unwrap();
        {
            let mut backend = batch.utxo_backend();
            let _ = apply_block(&mut backend, &genesis, 0, None::<fn(&str, u64)>).unwrap();
        }
        let hash = pow_hash(&genesis.header);
        batch.stage_block(0, &genesis).unwrap();
        let tip = TipInfo::new(0, hash, BigUint::zero(), 0);
        batch.stage_tip(&tip).unwrap();
        batch.commit().unwrap();

        let stored_tip = store.tip().unwrap().unwrap();
        assert_eq!(stored_tip.height, 0);
        assert_eq!(stored_tip.hash, hash);
    }

    #[test]
    fn rewind_updates_tip() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let params = ChainParams::default();
        let genesis = build_block([0u8; 32], 1, &params);
        commit_block(&store, &genesis, 0);
        let block1 = mine_next_block(&params, &genesis, 2);
        commit_block(&store, &block1, 1);
        let block2 = mine_next_block(&params, &block1, 3);
        commit_block(&store, &block2, 2);

        store.rewind_to(0).unwrap();
        let tip = store.tip().unwrap().unwrap();
        assert_eq!(tip.height, 0);
    }

    #[test]
    fn utxo_len_counts_entries() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.reset_utxo().unwrap();
        let mut utxo = store.new_utxo_store();
        let outpoint = utxo::OutPoint::new([7u8; 32], 0);
        let record = sample_record();
        utxo.insert(outpoint, record).unwrap();
        assert_eq!(store.utxo_len().unwrap(), 1);
    }

    fn commit_block(store: &Store, block: &Block, height: u64) {
        let mut batch = store.begin_block_batch().unwrap();
        {
            let mut backend = batch.utxo_backend();
            let _ = apply_block(&mut backend, block, height, None::<fn(&str, u64)>).unwrap();
        }
        batch.stage_block(height, block).unwrap();
        let hash = pow_hash(&block.header);
        let work = BigUint::zero();
        let tip = TipInfo::new(height, hash, work, 0);
        batch.stage_tip(&tip).unwrap();
        batch.commit().unwrap();
    }

    fn mine_next_block(params: &ChainParams, prev: &Block, seed: u64) -> Block {
        let tx = sample_tx(seed);
        let txs = vec![tx.clone()];
        let header = BlockHeader {
            version: 1,
            prev_hash: pow_hash(&prev.header),
            merkle_root: merkle_root(&txs),
            utxo_root: [0u8; 32],
            time: seed,
            n_bits: prev.header.n_bits,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, txs, &params.pow_limit)
    }

    fn build_block(prev_hash: [u8; 32], seed: u64, params: &ChainParams) -> Block {
        let tx = sample_tx(seed);
        let txs = vec![tx.clone()];
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: merkle_root(&txs),
            utxo_root: [0u8; 32],
            time: seed,
            n_bits: 0x207fffff,
            nonce: 0,
            alg_tag: 1,
        };
        mine_block(header, txs, &params.pow_limit)
    }

    fn sample_tx(seed: u64) -> tx::Tx {
        let material = KeyMaterial::random();
        let scan = material.derive_scan_keypair(0);
        let spend = material.derive_spend_keypair(0);
        let stealth = build_stealth_blob(&scan.public, &spend.public, &seed.to_le_bytes());
        TxBuilder::new()
            .add_output(Output::new(
                stealth,
                5000u64,
                OutputMeta {
                    deposit_flag: false,
                    deposit_id: None,
                },
            ))
            .set_witness(Witness::new(Vec::new(), seed, Vec::new()))
            .build()
    }

    fn sample_record() -> utxo::OutputRecord {
        utxo::OutputRecord::new(sample_output(0), 0, 0)
    }

    fn sample_output(seed: u64) -> Output {
        let material = KeyMaterial::random();
        let scan = material.derive_scan_keypair(0);
        let spend = material.derive_spend_keypair(0);
        let stealth = build_stealth_blob(&scan.public, &spend.public, &seed.to_le_bytes());
        Output::new(
            stealth,
            5000u64,
            OutputMeta {
                deposit_flag: false,
                deposit_id: None,
            },
        )
    }
}
