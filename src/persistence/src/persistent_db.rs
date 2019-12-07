/*
  Copyright (C) 2018-2019 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashMap;
use hashdb::{AsHashDB, HashDB};
use rlp::NULL_RLP;
use rocksdb::{ColumnFamily, DBCompactionStyle, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use crate::BlakeDbHasher;

pub fn cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_max_write_buffer_number(16);
    opts
}

pub fn db_options(wal_dir: &Path) -> Options {
    let mut opts = Options::default();
    let transform = rocksdb::SliceTransform::create_fixed_prefix(64); // Use a 64 byte prefix
    opts.set_prefix_extractor(transform);
    opts.set_wal_dir(wal_dir);
    opts.increase_parallelism(num_cpus::get() as i32);
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_max_open_files(10000);
    opts.set_use_fsync(false);
    opts.set_bytes_per_sync(8388608);
    opts.optimize_for_point_lookup(1024);
    opts.set_table_cache_num_shard_bits(6);
    opts.set_max_write_buffer_number(32);
    opts.set_write_buffer_size(536870912);
    opts.set_target_file_size_base(1073741824);
    opts.set_min_write_buffer_number_to_merge(4);
    opts.set_level_zero_stop_writes_trigger(2000);
    opts.set_level_zero_slowdown_writes_trigger(0);
    opts.set_compaction_style(DBCompactionStyle::Universal);
    opts.set_max_background_compactions(4);
    opts.set_max_background_flushes(4);
    opts.set_disable_auto_compactions(true);
    opts.set_memtable_prefix_bloom_ratio(0.2);
    opts
}

#[derive(PartialEq, Clone)]
pub enum Operation {
    Remove,
    Put(Vec<u8>),
}

#[derive(Clone)]
pub struct PersistentDb {
    pub db_ref: Option<Arc<DB>>,
    pub cf_name: Option<&'static str>,
    pub memory_db: HashMap<Vec<u8>, Operation>,
}

impl PersistentDb {
    pub const ROOT_HASH_KEY: &'static [u8] = b"root_hash";
    pub const RELOAD_FLAG: &'static [u8] = b"reload_flag";

    pub fn new(db_ref: Arc<DB>, cf_name: Option<&'static str>) -> PersistentDb {
        PersistentDb {
            db_ref: Some(db_ref),
            cf_name,
            memory_db: HashMap::new(),
        }
    }

    /// Creates a new in-memory `PersistentDb`.
    pub fn new_in_memory() -> PersistentDb {
        PersistentDb {
            db_ref: None,
            cf_name: None,
            memory_db: HashMap::new(),
        }
    }

    /// Commits the pending transactions to the db
    pub fn flush(&mut self) {
        let mut wipe = false;

        if let Some(ref db_ref) = self.db_ref {
            // Wipe memory if we have a database
            wipe = true;

            // Initialize a new transaction
            let mut batch = WriteBatch::default();

            let cf_handle = if let Some(cf) = self.cf_name {
                Some(db_ref.cf_handle(cf).unwrap())
            } else {
                None
            };

            for (key, val) in self.memory_db.iter() {
                match val {
                    Operation::Put(ref value) => {
                        if self.cf_name.is_some() {
                            batch.put_cf(cf_handle.unwrap(), &key, value).unwrap();
                        } else {
                            batch.put(&key, value).unwrap();
                        }
                    }

                    Operation::Remove => {
                        if self.cf_name.is_some() {
                            batch.delete_cf(cf_handle.unwrap(), key).unwrap();
                        } else {
                            batch.delete(key).unwrap();
                        }
                    }
                }
            }

            // Commit the transactions
            db_ref.write(batch).unwrap();
        }

        if wipe {
            // Wipe pending state
            self.wipe_memory();
        }
    }

    /// Clears the added transactions
    pub fn wipe_memory(&mut self) {
        self.memory_db.clear();
    }

    /// Gets the value directly from the db. This
    /// will not search pending transactions.
    pub fn retrieve_from_db(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.db_ref.is_some() {
            self.get_db(key)
        } else {
            let result = self.memory_db.get(key);

            if let Some(Operation::Put(ref val)) = result {
                Some(val.clone())
            } else {
                None
            }
        }
    }

    /// Gets the value based on the provided key
    pub fn retrieve(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.db_ref.is_some() {
            match self.memory_db.get(key) {
                Some(res) => match res {
                    Operation::Put(ref val) => Some(val.clone()),
                    Operation::Remove => None,
                },
                None => match self.get_db(key) {
                    Some(res) => Some(res),
                    None => match key {
                        Self::ROOT_HASH_KEY => Some(Hash::NULL_RLP.0.to_vec()),
                        _ => None,
                    },
                },
            }
        } else {
            let result = self.memory_db.get(key);

            if let Some(Operation::Put(ref val)) = result {
                Some(val.clone())
            } else {
                None
            }
        }
    }

    /// Sets a value for a specified key
    /// # Remarks
    /// Transactions will be commited when flush is called
    pub fn put(&mut self, key: &[u8], val: &[u8]) {
        self.memory_db
            .insert(key.to_vec(), Operation::Put(val.to_vec()));
    }

    /// Removes a value from the specified key
    /// # Remarks
    /// Transactions will be committed when flush is called
    pub fn delete(&mut self, key: &[u8]) {
        self.memory_db.insert(key.to_vec(), Operation::Remove);
    }

    /// Returns an iterator over entries with keys that have the provided prefix. Note that prefixes must be 64 bytes in length for maximum efficiency.
    pub fn prefix_iterator<'a, P: 'a + AsRef<[u8]> + Clone>(&'a self, prefix: P) -> Box<dyn Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a> {
        let prefix_clone = prefix.clone();
        let prefix_clone2 = prefix.clone();
        let mem_db_iter = self.memory_db
            .iter()
            .filter(move |(k, _v)| matches_prefix(k.as_ref(), prefix.clone()))
            .filter_map(|(k, op)| {
                if let Operation::Put(value) = op {
                    Some((k.clone().into_boxed_slice(), value.clone().into_boxed_slice()))
                } else {
                    None
                }
            });
        
        if let Some(db_ref) = &self.db_ref {
            let memory_db = &self.memory_db;
            
            Box::new(
                db_ref
                    .prefix_iterator(prefix_clone)
                    .filter(move |(k, _v)| matches_prefix(k.as_ref(), prefix_clone2.clone()))
                    .filter(move |(k, _v)| !memory_db.get(&k.to_vec()).is_some())
                    .chain(mem_db_iter)
            )
        } else {
            Box::new(mem_db_iter)
        }
    }

    fn get_db(&self, key: &[u8]) -> Option<Vec<u8>> {
        let db_ref = self.db_ref.as_ref().unwrap();

        if let Some(cf) = self.cf_name {
            let cf = db_ref.cf_handle(cf).unwrap();

            match db_ref.get_cf(cf, &key) {
                Ok(result) => match result {
                    Some(res) => Some(res.to_vec()),
                    None => None,
                },
                Err(err) => panic!(err),
            }
        } else {
            match db_ref.get(&key) {
                Ok(result) => match result {
                    Some(res) => Some(res.to_vec()),
                    None => None,
                },
                Err(err) => panic!(err),
            }
        }
    }
}

fn matches_prefix<P: AsRef<[u8]>>(key: &[u8], prefix: P) -> bool {
    let prefix = prefix.as_ref();

    if key.len() < prefix.len() {
        false
    } else {
        let mut key_hasher = DefaultHasher::new();
        let mut prefix_hasher = DefaultHasher::new();

        key_hasher.write(&key[..prefix.len()]);
        prefix_hasher.write(prefix);

        let key_digest = key_hasher.finish();
        let prefix_digest = prefix_hasher.finish();

        key_digest == prefix_digest 
    }
}

impl std::fmt::Debug for PersistentDb {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PersistentDb {{ cf: {:?} }}", self.cf_name)
    }
}

impl PartialEq for PersistentDb {
    fn eq(&self, other: &PersistentDb) -> bool {
        self.cf_name == other.cf_name
    }
}

impl HashDB<BlakeDbHasher, ElasticArray128<u8>> for PersistentDb {
    fn keys(&self) -> std::collections::HashMap<Hash, i32> {
        unimplemented!();
    }

    fn get(&self, key: &Hash) -> Option<ElasticArray128<u8>> {
        if key == &Hash::NULL_RLP {
            return Some(ElasticArray128::from_slice(&NULL_RLP));
        }

        if let Some(ref result) = self.retrieve(&key.0) {
            Some(ElasticArray128::<u8>::from_slice(result))
        } else {
            None
        }
    }

    fn insert(&mut self, val: &[u8]) -> Hash {
        if val == &NULL_RLP {
            return Hash::NULL_RLP;
        }

        let val_hash = crypto::hash_slice(val);
        self.put(&val_hash.0, val);

        val_hash
    }

    fn contains(&self, key: &Hash) -> bool {
        if key == &Hash::NULL_RLP {
            return true;
        }

        self.retrieve(&key.0).is_some()
    }

    fn emplace(&mut self, key: Hash, val: ElasticArray128<u8>) {
        if key == Hash::NULL_RLP {
            return;
        }

        self.put(&key.0, &val);
    }

    fn remove(&mut self, key: &Hash) {
        if key == &Hash::NULL_RLP {
            return;
        }

        self.delete(&key.0);
    }
}

impl AsHashDB<BlakeDbHasher, ElasticArray128<u8>> for PersistentDb {
    fn as_hashdb(&self) -> &HashDB<BlakeDbHasher, ElasticArray128<u8>> {
        self
    }
    fn as_hashdb_mut(&mut self) -> &mut HashDB<BlakeDbHasher, ElasticArray128<u8>> {
        self
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempdir::TempDir;
    use hashbrown::HashSet;

    #[test]
    fn prefix_iterator_flushed() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let prefix = hex::encode(crypto::hash_slice(b"prefix").0);
        let prefix1 = format!("{}.1", prefix);
        let prefix2 = format!("{}.2", prefix);
        let prefix3 = format!("{}.3", prefix);

        persistent_db.put(b"test", b"non_prefixed_data");
        persistent_db.put(b"test2", b"non_prefixed_data");
        persistent_db.put(b"test3", b"non_prefixed_data");
        persistent_db.put(b"test4", b"non_prefixed_data");
        persistent_db.put(b"test5", b"non_prefixed_data");
        persistent_db.put(b"test6", b"non_prefixed_data");
        persistent_db.put(b"test7", b"non_prefixed_data");
        persistent_db.put(b"test8", b"non_prefixed_data");
        persistent_db.put(prefix1.as_bytes(), b"test_data1");
        persistent_db.put(prefix2.as_bytes(), b"test_data2");
        persistent_db.put(prefix3.as_bytes(), b"test_data3");

        persistent_db.flush();

        let oracle_set = set![(prefix1.as_bytes().to_vec().into_boxed_slice(), b"test_data1".to_vec().into_boxed_slice()), (prefix2.as_bytes().to_vec().into_boxed_slice(), b"test_data2".to_vec().into_boxed_slice()), (prefix3.as_bytes().to_vec().into_boxed_slice(), b"test_data3".to_vec().into_boxed_slice())];
        assert!(oracle_set == persistent_db.prefix_iterator(prefix.as_bytes()).collect());
    }

    #[test]
    fn prefix_iterator_not_flushed() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);

        persistent_db.put(b"test", b"non_prefixed_data");
        persistent_db.put(b"prefix.1", b"test_data1");
        persistent_db.put(b"prefix.2", b"test_data2");
        persistent_db.put(b"prefix.3", b"test_data3");

        persistent_db.flush();

        persistent_db.put(b"prefix.4", b"test_data4");
        persistent_db.put(b"prefix.2", b"test_data5");

        let oracle_set = set![(b"prefix.1".to_vec().into_boxed_slice(), b"test_data1".to_vec().into_boxed_slice()), (b"prefix.2".to_vec().into_boxed_slice(), b"test_data5".to_vec().into_boxed_slice()), (b"prefix.3".to_vec().into_boxed_slice(), b"test_data3".to_vec().into_boxed_slice()), (b"prefix.4".to_vec().into_boxed_slice(), b"test_data4".to_vec().into_boxed_slice())];
        assert!(oracle_set == persistent_db.prefix_iterator(b"prefix").collect());
    }

    #[test]
    fn prefix_iterator_mem_db() {
        let mut persistent_db = PersistentDb::new_in_memory();

        persistent_db.put(b"test", b"non_prefixed_data");
        persistent_db.put(b"prefix.1", b"test_data1");
        persistent_db.put(b"prefix.2", b"test_data2");
        persistent_db.put(b"prefix.3", b"test_data3");

        let oracle_set = set![(b"prefix.1".to_vec().into_boxed_slice(), b"test_data1".to_vec().into_boxed_slice()), (b"prefix.2".to_vec().into_boxed_slice(), b"test_data2".to_vec().into_boxed_slice()), (b"prefix.3".to_vec().into_boxed_slice(), b"test_data3".to_vec().into_boxed_slice())];
        assert!(oracle_set == persistent_db.prefix_iterator(b"prefix").collect());
    }

    #[test]
    fn it_inserts_data() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);
        persistent_db.flush();
        assert_eq!(persistent_db.get(&key).unwrap().to_vec(), data.to_vec());
    }

    #[test]
    fn it_emplaces_data() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let db2 = persistent_db.clone();
        let key = crypto::hash_slice(b"the_key");
        let data = b"Hello world";

        persistent_db.emplace(key, ElasticArray128::from_slice(data));
        assert!(db2.get(&key).is_none());
        persistent_db.flush();
        assert_eq!(
            persistent_db.retrieve_from_db(&key.0).unwrap(),
            data.to_vec()
        );
        assert_eq!(db2.get(&key).unwrap(), data.to_vec());
    }

    #[test]
    fn contains() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);
        persistent_db.flush();
        assert!(persistent_db.contains(&key));
    }

    #[test]
    fn remove() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);

        persistent_db.flush();
        assert!(persistent_db.contains(&key));

        persistent_db.remove(&key);
        persistent_db.flush();
        assert!(!persistent_db.contains(&key));
    }

    #[test]
    fn it_keeps_last_operation_per_key() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);
        persistent_db.remove(&key);
        persistent_db.flush();
        assert!(!persistent_db.contains(&key));

        let key = persistent_db.insert(data);
        persistent_db.flush();
        assert!(persistent_db.contains(&key));
    }

    #[test]
    fn it_looks_into_pending_transactions() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);
        assert!(persistent_db.contains(&key));
        assert!(persistent_db.get(&key).is_some());
        assert!(persistent_db.retrieve(&key.0.to_vec()).is_some());
        assert!(persistent_db.retrieve_from_db(&key.0.to_vec()).is_none());

        persistent_db.flush();
        assert!(persistent_db.contains(&key));
        assert!(persistent_db.get(&key).is_some());
        assert!(persistent_db.retrieve(&key.0.to_vec()).is_some());
        assert!(persistent_db.retrieve_from_db(&key.0.to_vec()).is_some());
    }

    #[test]
    fn it_doesnt_write_until_flush() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);
        assert!(persistent_db.retrieve_from_db(&key.0.to_vec()).is_none());

        persistent_db.flush();
        assert!(persistent_db.retrieve_from_db(&key.0.to_vec()).is_some());
    }

    #[test]
    fn wipe_works() {
        let dir = TempDir::new("purple_test").unwrap();
        let path = dir.path().join("database");
        let path = path.to_str().unwrap();
        let db = DB::open_default(path).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";
        let data2 = b"Hello world 2";
        let data3 = b"Hello world 3";

        let key = persistent_db.insert(data);
        let key2 = persistent_db.insert(data2);
        let key3 = persistent_db.insert(data3);
        persistent_db.wipe_memory();

        assert!(persistent_db.get(&key).is_none());
        assert!(persistent_db.get(&key2).is_none());
        assert!(persistent_db.get(&key3).is_none());
    }
}
