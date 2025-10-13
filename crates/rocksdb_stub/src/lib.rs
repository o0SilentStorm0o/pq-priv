use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub mod checkpoint;

#[derive(Debug, Clone)]
pub struct Error(String);

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    create_if_missing: bool,
    create_missing_column_families: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            create_if_missing: true,
            create_missing_column_families: true,
        }
    }
}

impl Options {
    pub fn create_if_missing(&mut self, value: bool) {
        self.create_if_missing = value;
    }

    pub fn create_missing_column_families(&mut self, value: bool) {
        self.create_missing_column_families = value;
    }
}

#[derive(Debug, Clone)]
pub struct ColumnFamilyDescriptor {
    name: String,
    options: Options,
}

impl ColumnFamilyDescriptor {
    pub fn new(name: impl Into<String>, options: Options) -> Self {
        Self {
            name: name.into(),
            options,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn options(&self) -> &Options {
        &self.options
    }
}

#[derive(Debug)]
struct Inner {
    _path: PathBuf,
    columns: HashMap<String, Arc<ColumnFamily>>,
}

#[derive(Clone)]
pub struct DB {
    inner: Arc<Inner>,
}

impl DB {
    pub fn open_cf_descriptors(
        opts: &Options,
        path: impl AsRef<Path>,
        descriptors: Vec<ColumnFamilyDescriptor>,
    ) -> Result<Self, Error> {
        let path = path.as_ref();
        if opts.create_if_missing {
            std::fs::create_dir_all(path)?;
        }
        let mut columns = HashMap::new();
        for descriptor in descriptors {
            let file = path.join(format!("{}.cf", descriptor.name()));
            let cf = ColumnFamily::new(descriptor.name().to_string(), file)?;
            columns.insert(cf.name().to_string(), Arc::new(cf));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                _path: path.to_path_buf(),
                columns,
            }),
        })
    }

    pub fn get_cf<K>(&self, cf: &ColumnFamily, key: K) -> Result<Option<Vec<u8>>, Error>
    where
        K: AsRef<[u8]>,
    {
        let data = cf.data.read().map_err(|_| Error::new("lock poisoned"))?;
        Ok(data.get(key.as_ref()).cloned().map(|v| v.to_vec()))
    }

    pub fn put_cf<K, V>(&self, cf: &ColumnFamily, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        cf.insert(key, value)
    }

    pub fn put_cf_opt<K, V>(
        &self,
        cf: &ColumnFamily,
        key: K,
        value: V,
        _opts: &WriteOptions,
    ) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.put_cf(cf, key, value)
    }

    pub fn delete_cf<K>(&self, cf: &ColumnFamily, key: K) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
    {
        cf.remove(key)
    }

    pub fn delete_cf_opt<K>(
        &self,
        cf: &ColumnFamily,
        key: K,
        _opts: &WriteOptions,
    ) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
    {
        self.delete_cf(cf, key)
    }

    pub fn iterator_cf(
        &self,
        cf: &ColumnFamily,
        _mode: IteratorMode,
    ) -> DBIterator {
        let data = cf
            .data
            .read()
            .map(|map| map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        DBIterator { entries: data, index: 0 }
    }

    pub fn write_opt(&self, batch: WriteBatch, _opts: &WriteOptions) -> Result<(), Error> {
        for op in batch.ops {
            let Some(cf) = self.inner.columns.get(&op.cf_name) else {
                return Err(Error::new(format!(
                    "unknown column family: {}",
                    op.cf_name
                )));
            };
            match op.kind {
                BatchOpKind::Put { key, value } => {
                    cf.as_ref().insert(key, value)?;
                }
                BatchOpKind::Delete { key } => {
                    cf.as_ref().remove(key)?;
                }
            }
        }
        Ok(())
    }

    pub fn property_int_value(&self, _name: &str) -> Result<Option<u64>, Error> {
        Ok(Some(0))
    }

    pub fn cf_handle(&self, name: &str) -> Option<&ColumnFamily> {
        self.inner
            .columns
            .get(name)
            .map(|cf| cf.as_ref())
    }
}

#[derive(Debug)]
pub struct ColumnFamily {
    name: String,
    data: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
    path: PathBuf,
}

impl ColumnFamily {
    fn new(name: String, path: PathBuf) -> Result<Self, Error> {
        let data = Arc::new(RwLock::new(Self::load_from_disk(&path)?));
        Ok(Self { name, data, path })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn insert<K, V>(&self, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut data = self.data.write().map_err(|_| Error::new("lock poisoned"))?;
        data.insert(key.as_ref().to_vec(), value.as_ref().to_vec());
        self.persist(&data)
    }

    fn remove<K>(&self, key: K) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
    {
        let mut data = self.data.write().map_err(|_| Error::new("lock poisoned"))?;
        data.remove(key.as_ref());
        self.persist(&data)
    }

    fn load_from_disk(path: &Path) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
        let mut map = BTreeMap::new();
        let Ok(raw) = fs::read(path) else {
            return Ok(map);
        };
        let mut cursor = raw.as_slice();
        while cursor.len() >= 8 {
            let key_len = u32::from_le_bytes(cursor[0..4].try_into().unwrap()) as usize;
            let value_len = u32::from_le_bytes(cursor[4..8].try_into().unwrap()) as usize;
            cursor = &cursor[8..];
            if cursor.len() < key_len + value_len {
                return Err(Error::new("corrupted column family data"));
            }
            let key = cursor[..key_len].to_vec();
            cursor = &cursor[key_len..];
            let value = cursor[..value_len].to_vec();
            cursor = &cursor[value_len..];
            map.insert(key, value);
        }
        Ok(map)
    }

    fn persist(&self, data: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::new();
        for (key, value) in data {
            let key_len = key.len() as u32;
            let value_len = value.len() as u32;
            bytes.extend_from_slice(&key_len.to_le_bytes());
            bytes.extend_from_slice(&value_len.to_le_bytes());
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(value);
        }
        fs::write(&self.path, bytes)?;
        Ok(())
    }
}

pub struct DBIterator {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    index: usize,
}

impl Iterator for DBIterator {
    type Item = Result<(Vec<u8>, Vec<u8>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.entries.len() {
            return None;
        }
        let item = self.entries[self.index].clone();
        self.index += 1;
        Some(Ok(item))
    }
}

#[derive(Debug, Default, Clone)]
pub struct WriteOptions {
    disable_wal: bool,
}

impl WriteOptions {
    pub fn disable_wal(&mut self, value: bool) {
        self.disable_wal = value;
    }
}

#[derive(Default)]
pub struct WriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch {
    pub fn put_cf<K, V>(&mut self, cf: &ColumnFamily, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.ops.push(BatchOp {
            cf_name: cf.name().to_string(),
            kind: BatchOpKind::Put {
                key: key.as_ref().to_vec(),
                value: value.as_ref().to_vec(),
            },
        });
    }

    pub fn delete_cf<K>(&mut self, cf: &ColumnFamily, key: K)
    where
        K: AsRef<[u8]>,
    {
        self.ops.push(BatchOp {
            cf_name: cf.name().to_string(),
            kind: BatchOpKind::Delete {
                key: key.as_ref().to_vec(),
            },
        });
    }
}

struct BatchOp {
    cf_name: String,
    kind: BatchOpKind,
}

enum BatchOpKind {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

#[derive(Debug, Clone, Copy)]
pub enum IteratorMode {
    Start,
}
