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

use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashMap;
use hashdb::{AsHashDB, HashDB};
use kvdb::DBTransaction;
use kvdb_rocksdb::Database;
use rlp::NULL_RLP;
use std::sync::Arc;
use BlakeDbHasher;

#[derive(Clone)]
pub struct PersistentDb {
    db_ref: Option<Arc<Database>>,
    cf: Option<u32>,
    tx: Option<DBTransaction>,
    memory_db: Option<HashMap<Vec<u8>, Vec<u8>>>,
}

trait BasicOperations<T> {
    fn retrieve(&self, key: &[T]) -> Option<Vec<T>>; //renamed from get
    fn put(&mut self, key: &[T], val: &[T]);
    fn delete(&mut self, key: &[T]); //renamed from remove
}

impl PersistentDb {
    pub fn new(db_ref: Arc<Database>, cf: Option<u32>) -> PersistentDb {
        PersistentDb {
            db_ref: Some(db_ref),
            cf: cf,
            tx: None,
            memory_db: None,
        }
    }

    /// Creates a new in-memory `PersistentDb`.
    pub fn new_in_memory() -> PersistentDb {
        PersistentDb {
            db_ref: None,
            cf: None,
            tx: None,
            memory_db: Some(HashMap::new()),
        }
    }

    /// Commits the pending transactions to the db
    pub fn flush(&mut self) {
        // The case when db_ref.is_none and tx.is_some is not a realistic one,
        // because tx is a DBTransaction created from db_ref
        if let (Some(db_ref), Some(tx)) = (&self.db_ref, &self.tx) {
            // Commit the transactions to the db
            db_ref.write(tx.clone()).unwrap();
        } else if let (Some(db_ref), None) = (&self.db_ref, &self.tx) {
            warn!("Unnecessarily called flush before doing any transaction");
        } else if let (None, None) = (&self.db_ref, &self.tx) {
            warn!("Unnecessarily called flush because no db reference can be found")
        }

        // Wipe pending state
        self.wipe();
    }

    /// Clears the added transactions
    pub fn wipe(&mut self) {
        if let Some(db_ref) = &self.db_ref {
            self.tx = Some(db_ref.transaction());
        }
    }
}

impl std::fmt::Debug for PersistentDb {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PersistentDb {{ cf: {:?} }}", self.cf)
    }
}

impl BasicOperations<u8> for PersistentDb {
    /// Gets the value based on the provided key
    fn retrieve(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(db_ref) = &self.db_ref {
            match db_ref.get(self.cf, &key) {
                Ok(result) => Some(result.unwrap().into_vec()),
                Err(err) => panic!(err),
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
    fn put(&mut self, key: &[u8], val: &[u8]) {
        if let Some(db_ref) = &self.db_ref {
            if self.tx.is_none() {
                self.tx = Some(db_ref.transaction());
            }

            self.tx.clone().unwrap().put(self.cf, key, val);
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
    fn delete(&mut self, key: &[u8]) {
        if let Some(db_ref) = &self.db_ref {
            if self.tx.is_none() {
                self.tx = Some(db_ref.transaction());
            }

            self.tx.clone().unwrap().delete(self.cf, &key.to_vec());
        } else {
            let mut memory_db = self.memory_db.as_mut().unwrap();
            memory_db.remove(&key.to_vec());
        }
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
}
