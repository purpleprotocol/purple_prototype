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

use crate::BlakeDbHasher;
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashMap;
use hashdb::{AsHashDB, HashDB};
use kvdb::DBTransaction;
use kvdb_rocksdb::Database;
use rlp::NULL_RLP;
use std::sync::Arc;

#[derive(PartialEq, Clone)]
enum Operation {
    Remove,
    Put,
}

#[derive(Clone)]
struct OperationInfo {
    op: Operation,
    val: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct PersistentDb {
    db_ref: Option<Arc<Database>>,
    cf: Option<u32>,
    reg: Option<HashMap<Vec<u8>, OperationInfo>>,
    memory_db: Option<HashMap<Vec<u8>, Vec<u8>>>,
}

impl PersistentDb {
    pub fn new(db_ref: Arc<Database>, cf: Option<u32>) -> PersistentDb {
        PersistentDb {
            db_ref: Some(db_ref),
            cf: cf,
            reg: None,
            memory_db: None,
        }
    }

    /// Creates a new in-memory `PersistentDb`.
    pub fn new_in_memory() -> PersistentDb {
        PersistentDb {
            db_ref: None,
            cf: None,
            reg: None,
            memory_db: Some(HashMap::new()),
        }
    }

    /// Commits the pending transactions to the db
    pub fn flush(&mut self) {
        // The case when db_ref.is_none and reg.is_some is not a realistic one,
        // because HashMap registry is not used for db_ref
        match (&self.db_ref, &self.reg) {
            (Some(db_ref), Some(reg)) => {
                // Initialize a new transaction
                let mut tx: DBTransaction = db_ref.transaction();

                // Load all the pending transactions into the DBTransaction
                for (key, val) in reg.iter() {
                    match val.op {
                        Operation::Put => match val.val {
                            Some(ref value) => tx.put(self.cf, &key, value),
                            None => {
                                panic!("Tried to do an insert operation without providing value")
                            }
                        },
                        Operation::Remove => tx.delete(self.cf, key),
                    }
                }

                // Commit the transactions
                db_ref.write(tx).unwrap()
            }
            (Some(_db_ref), None) => {
                warn!("Unnecessarily called flush before doing any transaction")
            }
            (None, None) => {
                warn!("Unnecessarily called flush because no db reference can be found")
            }
            (None, Some(_reg)) => panic!("Transactions cannot exist while the db is None"),
        }

        // Wipe pending state
        self.wipe();
    }

    /// Clears the added transactions
    pub fn wipe(&mut self) {
        if let Some(ref mut reg) = self.reg {
            reg.clear();
        }
    }

    /// Gets the value directly from the db
    /// # Remarks
    /// Pending transactions will not be searched
    pub fn retrieve_from_db(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(db_ref) = &self.db_ref {
            match db_ref.get(self.cf, &key) {
                Ok(result) => match result {
                    Some(res) => Some(res.into_vec()),
                    None => None,
                },
                Err(err) => panic!(err),
            }
        } else {
            let memory_db = self.memory_db.as_ref().unwrap();
            let result = memory_db.get(&key.to_vec());

            result.cloned()
        }
    }

    /// Gets the value based on the provided key
    pub fn retrieve(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(db_ref) = &self.db_ref {
            if let Some(reg) = &self.reg {
                // A registry exists, need to check the value from there
                match reg.get(&key.to_vec()) {
                    Some(res) => match res.op {
                        Operation::Put => res.val.as_ref().cloned(),
                        Operation::Remove => None,
                    },
                    None => match db_ref.get(self.cf, &key) {
                        Ok(result) => match result {
                            Some(res) => Some(res.into_vec()),
                            None => None,
                        },

                        Err(err) => panic!(err),
                    },
                }
            } else {
                match db_ref.get(self.cf, &key) {
                    Ok(result) => match result {
                        Some(res) => Some(res.into_vec()),
                        None => None,
                    },

                    Err(err) => panic!(err),
                }
            }
        } else {
            let memory_db = self.memory_db.as_ref().unwrap();
            let result = memory_db.get(&key.to_vec());

            result.cloned()
        }
    }

    /// Sets a value for a specified key
    /// # Remarks
    /// Transactions will be commited when flush is called
    pub fn put(&mut self, key: &[u8], val: &[u8]) {
        if let Some(_db_ref) = &self.db_ref {
            if self.reg.is_none() {
                self.reg = Some(HashMap::new());
            }

            // Add the pending insert to the registry HashMap
            let value = OperationInfo {
                op: Operation::Put,
                val: Some(val.to_vec()),
            };

            self.reg.as_mut().unwrap().insert(key.to_vec(), value);
        } else {
            self.memory_db
                .as_mut()
                .unwrap()
                .insert(key.to_vec(), val.to_vec());
        }
    }

    /// Removes a value from the specified key
    /// # Remarks
    /// Transactions will be commited when flush is called
    pub fn delete(&mut self, key: &[u8]) {
        if let Some(_db_ref) = &self.db_ref {
            if self.reg.is_none() {
                self.reg = Some(HashMap::new());
            }

            // Add the pending delete to the registry HashMap
            let value = OperationInfo {
                op: Operation::Remove,
                val: None,
            };

            self.reg.as_mut().unwrap().insert(key.to_vec(), value);
        } else {
            let mut memory_db = self.memory_db.as_mut().unwrap();
            memory_db.remove(&key.to_vec());
        }
    }
}

impl std::fmt::Debug for PersistentDb {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PersistentDb {{ cf: {:?} }}", self.cf)
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
    use kvdb_rocksdb::DatabaseConfig;
    use tempdir::TempDir;

    #[test]
    fn it_inserts_data() {
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);
        persistent_db.flush();
        assert_eq!(persistent_db.get(&key).unwrap().to_vec(), data.to_vec());
    }

    #[test]
    fn it_emplaces_data() {
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
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
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);
        persistent_db.flush();
        assert!(persistent_db.contains(&key));
    }

    #[test]
    fn remove() {
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
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
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
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
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
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
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
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
        let config = DatabaseConfig::with_columns(None);
        let dir = TempDir::new("purple_test").unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";
        let data2 = b"Hello world 2";
        let data3 = b"Hello world 3";

        let key = persistent_db.insert(data);
        let key2 = persistent_db.insert(data2);
        let key3 = persistent_db.insert(data3);
        persistent_db.wipe();

        assert!(persistent_db.get(&key).is_none());
        assert!(persistent_db.get(&key2).is_none());
        assert!(persistent_db.get(&key3).is_none());
    }
}
