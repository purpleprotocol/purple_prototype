/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

use common::{Checkpointable, StorageLocation};
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashMap;
use hashdb::{AsHashDB, HashDB};
use rlp::NULL_RLP;
use rocksdb::{ColumnFamily, DBCompactionStyle, Options, WriteBatch, DB};
use std::sync::Arc;
use BlakeDbHasher;

pub fn cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_max_write_buffer_number(16);
    opts
}

pub fn db_options() -> Options {
    let mut opts = Options::default();
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
    opts
}

#[derive(PartialEq, Clone)]
enum Operation {
    Remove,
    Put(Vec<u8>),
}

#[derive(Clone)]
pub struct PersistentDb {
    db_ref: Option<Arc<DB>>,
    cf_name: Option<&'static str>,
    memory_db: HashMap<Vec<u8>, Operation>,
}

impl PersistentDb {
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
                            batch.delete_cf(cf_handle.unwrap(), key);
                        } else {
                            batch.delete(key);
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
        if let Some(db_ref) = &self.db_ref {
            match self.memory_db.get(key) {
                Some(res) => match res {
                    Operation::Put(ref val) => Some(val.clone()),
                    Operation::Remove => None,
                },
                None => self.get_db(key),
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
    /// Transactions will be commited when flush is called
    pub fn delete(&mut self, key: &[u8]) {
        self.memory_db.insert(key.to_vec(), Operation::Remove);
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

impl Checkpointable for PersistentDb {
    fn checkpoint(&self) -> u64 {
        unimplemented!();
    }

    fn delete_checkpoint(id: u64) -> Result<(), ()> {
        unimplemented!();
    }

    fn load_from_disk(id: u64) -> Result<PersistentDb, ()> {
        unimplemented!();
    }

    fn storage_location(&self) -> StorageLocation {
        unimplemented!();
    }
}

impl std::fmt::Debug for PersistentDb {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PersistentDb {{ cf: {:?} }}", self.cf_name)
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

        let result = self.retrieve(&key.0.to_vec());
        if result.is_some() {
            Some(ElasticArray128::<u8>::from_slice(&result.unwrap()))
        } else {
            None
        }
    }

    fn insert(&mut self, val: &[u8]) -> Hash {
        if val == &NULL_RLP {
            return Hash::NULL_RLP;
        }

        let val_hash = crypto::hash_slice(val);
        self.put(&val_hash.0.to_vec(), val);

        val_hash
    }

    fn contains(&self, key: &Hash) -> bool {
        if key == &Hash::NULL_RLP {
            return true;
        }

        self.retrieve(&key.0.to_vec()).is_some()
    }

    fn emplace(&mut self, key: Hash, val: ElasticArray128<u8>) {
        if &val == &Hash::NULL_RLP.to_vec() {
            return;
        }

        self.put(&key.0.to_vec(), &val);
    }

    fn remove(&mut self, key: &Hash) {
        if key == &Hash::NULL_RLP {
            return;
        }

        self.delete(&key.0.to_vec());
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn it_inserts_data() {
        let dir = TempDir::new("purple_test").unwrap();
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
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
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let key = crypto::hash_slice(b"the_key");
        let data = b"Hello world";

        persistent_db.emplace(key, ElasticArray128::from_slice(data));
        persistent_db.flush();
        assert_eq!(persistent_db.get(&key).unwrap().to_vec(), data.to_vec());
    }

    #[test]
    fn contains() {
        let dir = TempDir::new("purple_test").unwrap();
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
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
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
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
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
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
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
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
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
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
        let db = DB::open_default(dir.path().to_str().unwrap()).unwrap();
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
