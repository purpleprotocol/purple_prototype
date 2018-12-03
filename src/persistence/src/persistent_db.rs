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

use std::sync::Arc;
use kvdb_rocksdb::Database;
use hashdb::{HashDB, AsHashDB};
use std::collections::HashMap;
use crypto::Hash;
use Hasher;

pub struct PersistentDb {
    db_ref: Arc<Database>,
    cf: Option<u32>
}

impl PersistentDb {
    pub fn new(db_ref: Arc<Database>, cf: Option<u32>) -> PersistentDb {
        PersistentDb {
            db_ref: db_ref,
            cf: cf
        }
    }
}

impl HashDB<Hasher, Vec<u8>> for PersistentDb {
    fn keys(&self) -> HashMap<Hash, i32> {
        unimplemented!();
    }

    fn get(&self, key: &Hash) -> Option<Vec<u8>> {
        let db_ref = &self.db_ref;

        match db_ref.get(self.cf, &*key.0.to_vec()) {
            Ok(result) => {
                if let Some(res) = result {
                    Some(res.to_vec())
                } else {
                    None
                }
            },
            Err(err) => panic!(err)
        }
    }

    fn insert(&mut self, val: &[u8]) -> Hash {
        let db_ref = &self.db_ref;
        let val_hash = crypto::hash_slice(val);
        let mut tx = db_ref.transaction();
		
        // Write item to db
        tx.put(self.cf, &val_hash.0.to_vec(), val);
		db_ref.write(tx).unwrap();

        val_hash
    }

    fn contains(&self, key: &Hash) -> bool {
        let db_ref = &self.db_ref;

        match db_ref.get(self.cf, &*key.0.to_vec()) {
            Ok(result) => {
                if let Some(_) = result {
                    true
                } else {
                    false
                }
            },
            Err(err) => panic!(err)
        }
    }

    fn emplace(&mut self, key: Hash, val: Vec<u8>) {
        let db_ref = &self.db_ref;
        let mut tx = db_ref.transaction();
		
        // Write item to db
        tx.put(self.cf, &key.0.to_vec(), &val);
		db_ref.write(tx).unwrap();
    }

    fn remove(&mut self, key: &Hash) {
        let db_ref = &self.db_ref;
        let mut tx = db_ref.transaction();
		
        tx.delete(self.cf, &key.0.to_vec());
		db_ref.write(tx).unwrap();
    }
}

impl AsHashDB<Hasher, Vec<u8>> for PersistentDb {
    fn as_hashdb(&self) -> &HashDB<Hasher, Vec<u8>> { self }
    fn as_hashdb_mut(&mut self) -> &mut HashDB<Hasher, Vec<u8>> { self }
}

#[cfg(test)] 
mod tests {
    use super::*;
    use tempfile::tempdir;
    use kvdb_rocksdb::DatabaseConfig;

    #[test]
    fn it_inserts_data() {
        let config = DatabaseConfig::with_columns(None);
        let dir = tempdir().unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);
        let mut persistent_db = PersistentDb::new(db_ref, None);
        let data = b"Hello world";

        let key = persistent_db.insert(data);

        assert_eq!(persistent_db.get(&key).unwrap(), data);
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

        persistent_db.emplace(key, data.to_vec());

        assert_eq!(persistent_db.get(&key).unwrap(), data);
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