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
use hashdb::{AsHashDB, HashDB};
use kvdb_rocksdb::Database;
use rlp::NULL_RLP;
use std::collections::HashMap;
use std::sync::Arc;
use BlakeDbHasher;

#[derive(Clone)]
pub struct PersistentDb {
    db_ref: Arc<Database>,
    cf: Option<u32>,
}

impl PersistentDb {
    pub fn new(db_ref: Arc<Database>, cf: Option<u32>) -> PersistentDb {
        PersistentDb {
            db_ref: db_ref,
            cf: cf,
        }
    }
}

impl std::fmt::Debug for PersistentDb {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PersistentDb {{ cf: {:?} }}", self.cf)
    }
}

impl HashDB<BlakeDbHasher, ElasticArray128<u8>> for PersistentDb {
    fn keys(&self) -> HashMap<Hash, i32> {
        unimplemented!();
    }

    fn get(&self, key: &Hash) -> Option<ElasticArray128<u8>> {
        if key == &Hash::NULL_RLP {
            return Some(ElasticArray128::from_slice(&NULL_RLP));
        }

        let db_ref = &self.db_ref;

        match db_ref.get(self.cf, &*key.0.to_vec()) {
            Ok(result) => result,
            Err(err) => panic!(err),
        }
    }

    fn insert(&mut self, val: &[u8]) -> Hash {
        if val == &NULL_RLP {
            return Hash::NULL_RLP;
        }

        let db_ref = &self.db_ref;
        let val_hash = crypto::hash_slice(val);
        let mut tx = db_ref.transaction();

        // Write item to db
        tx.put(self.cf, &val_hash.0.to_vec(), val);
        db_ref.write(tx).unwrap();

        val_hash
    }

    fn contains(&self, key: &Hash) -> bool {
        if key == &Hash::NULL_RLP {
            return true;
        }

        let db_ref = &self.db_ref;

        match db_ref.get(self.cf, &*key.0.to_vec()) {
            Ok(result) => {
                if let Some(_) = result {
                    true
                } else {
                    false
                }
            }
            Err(err) => panic!(err),
        }
    }

    fn emplace(&mut self, key: Hash, val: ElasticArray128<u8>) {
        if &val == &Hash::NULL_RLP.to_vec() {
            return;
        }

        let db_ref = &self.db_ref;
        let mut tx = db_ref.transaction();

        // Write item to db
        tx.put(self.cf, &key.0.to_vec(), &val);
        db_ref.write(tx).unwrap();
    }

    fn remove(&mut self, key: &Hash) {
        if key == &Hash::NULL_RLP {
            return;
        }

        let db_ref = &self.db_ref;
        let mut tx = db_ref.transaction();

        tx.delete(self.cf, &key.0.to_vec());
        db_ref.write(tx).unwrap();
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
    use tempfile::tempdir;

    #[test]
    fn it_inserts_data() {
        let config = DatabaseConfig::with_columns(None);
        let dir = tempdir().unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);

        assert_eq!(persistent_db.get(&key).unwrap().to_vec(), data.to_vec());
    }

    #[test]
    fn it_emplaces_data() {
        let config = DatabaseConfig::with_columns(None);
        let dir = tempdir().unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let key = crypto::hash_slice(b"the_key");
        let data = b"Hello world";

        persistent_db.emplace(key, ElasticArray128::from_slice(data));

        assert_eq!(persistent_db.get(&key).unwrap().to_vec(), data.to_vec());
    }

    #[test]
    fn contains() {
        let config = DatabaseConfig::with_columns(None);
        let dir = tempdir().unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);

        assert!(persistent_db.contains(&key));
    }

    #[test]
    fn remove() {
        let config = DatabaseConfig::with_columns(None);
        let dir = tempdir().unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);

        assert!(persistent_db.contains(&key));

        persistent_db.remove(&key);

        assert!(!persistent_db.contains(&key));
    }
}
