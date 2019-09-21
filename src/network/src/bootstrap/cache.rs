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

use crate::error::NetworkErr;
use crate::bootstrap::entry::BootstrapCacheEntry;
use persistence::PersistentDb;
use std::net::{IpAddr, SocketAddr};
use std::str;
use std::str::FromStr;

/// The key to the main bootstrap cache entry
const BOOTSTRAP_CACHE_PREFIX: &'static str = "bootstrap_cache";

/// The key of the current index
const CURRENT_IDX_KEY: &'static [u8] = b"current_index";

/// The key to the number of entries field
const ENTRIES_COUNT_KEY: &'static [u8] = b"entries_count";

#[derive(Clone, Debug)]
/// Interface to the bootstrap cache of the node. This stores
/// previously encountered node ips to which we can connect to
/// in the future. 
pub struct BootstrapCache {
    /// The underlying database instance.
    db: PersistentDb,

    /// The size of the bootstrap cache.
    cache_size: u64,
}

impl BootstrapCache {
    pub fn new(db: PersistentDb, cache_size: u64) -> BootstrapCache {
        BootstrapCache {
            db,
            cache_size,
        }
    }

    /// Returns true if the given address's ip is stored in the bootstrap cache.
    pub fn has_address(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        let ip_str = format!("{}", ip);
        let ip_hash = crypto::hash_slice(ip_str.as_bytes());

        self.db.retrieve(&ip_hash.0).is_some()
    }

    /// Stores the given address in the bootstrap cache.
    pub fn store_address(&mut self, addr: &SocketAddr) -> Result<(), NetworkErr> {
        let ip = addr.ip();
        let ip_str = format!("{}", ip);
        let ip_hash = crypto::hash_slice(ip_str.as_bytes());

        if self.db.retrieve(&ip_hash.0).is_some() {
            Err(NetworkErr::AlreadyStored)
        } else {
            if let Some(idx) = self.db.retrieve(CURRENT_IDX_KEY) {
                let entries_count = self.db.retrieve(ENTRIES_COUNT_KEY).unwrap();
                let mut entries_count = decode_be_u64!(entries_count).unwrap();
                entries_count += 1;
                let mut idx = decode_be_u64!(idx).unwrap();
                idx += 1;
                let entry_key = format!("{}.{}", hex::encode(crypto::hash_slice(BOOTSTRAP_CACHE_PREFIX.as_bytes()).0), idx);
                let encoded_idx = encode_be_u64!(idx);

                // Store entries count
                self.db.put(ENTRIES_COUNT_KEY, &encode_be_u64!(entries_count));

                // Store index
                self.db.put(CURRENT_IDX_KEY, &encoded_idx);

                // Store index mapping 
                self.db.put(&ip_hash.0, &encoded_idx);

                // Store address
                self.db.put(entry_key.as_bytes(), ip_str.as_bytes());
            } else {
                let entry_key = format!("{}.{}", hex::encode(crypto::hash_slice(BOOTSTRAP_CACHE_PREFIX.as_bytes()).0), 0);

                // Store entries length
                self.db.put(ENTRIES_COUNT_KEY, &[0, 0, 0, 0, 0, 0, 0, 1]);

                // Store first index
                self.db.put(CURRENT_IDX_KEY, &[0, 0, 0, 0, 0, 0, 0, 0]);

                // Store index mapping 
                self.db.put(&ip_hash.0, &[0, 0, 0, 0, 0, 0, 0, 0]);

                // Store address
                self.db.put(entry_key.as_bytes(), ip_str.as_bytes());
            }

            // Flush changes
            self.db.flush();

            Ok(())
        }
    }

    /// Deletes the entry with the ip of the given address from the bootstrap cache, if found.
    pub fn delete_address(&mut self, addr: &SocketAddr) -> Result<(), NetworkErr> {
        let ip = addr.ip();
        let ip_str = format!("{}", ip);
        let ip_hash = crypto::hash_slice(ip_str.as_bytes());

        if let Some(idx) = self.db.retrieve(&ip_hash.0) {
            let entries_count = self.db.retrieve(ENTRIES_COUNT_KEY).unwrap();
            let mut entries_count = decode_be_u64!(entries_count).unwrap();
            entries_count -= 1;
            let idx = decode_be_u64!(idx).unwrap();
            let entry_key = format!("{}.{}", hex::encode(crypto::hash_slice(BOOTSTRAP_CACHE_PREFIX.as_bytes()).0), idx);

            // Remove index mapping
            self.db.delete(&ip_hash.0);

            // Remove entry
            self.db.delete(entry_key.as_bytes());

            // Update entries count
            self.db.put(ENTRIES_COUNT_KEY, &encode_be_u64!(entries_count));

            // Flush changes
            self.db.flush();

            Ok(())
        } else {
            Ok(())
        }
    }

    /// Returns an iterator over the entries that are stored in the bootstrap cache.
    pub fn entries<'a>(&'a self) -> Box<dyn Iterator<Item = BootstrapCacheEntry> + 'a> {
        Box::new(
            self.db
                .prefix_iterator(hex::encode(crypto::hash_slice(BOOTSTRAP_CACHE_PREFIX.as_bytes()).0))
                .map(|(_k, v)| {
                    let ip_str = str::from_utf8(&v).unwrap();
                    let ip = IpAddr::from_str(&ip_str).unwrap();

                    BootstrapCacheEntry {
                        addr: ip
                    }
                })
        )
    }

    /// Return true if there are no entries stored in the bootstrap cache
    pub fn is_empty(&self) -> bool {
        if let Some(count) = self.db.retrieve(ENTRIES_COUNT_KEY) {
            let entries_count = decode_be_u64!(count).unwrap();
            entries_count == 0
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashSet;
    
    #[test]
    fn store_address() {
        let db = test_helpers::init_tempdb();
        let mut cache = BootstrapCache::new(db, 1000);
        let addr = crate::random_socket_addr();

        assert!(cache.is_empty());
        assert!(!cache.has_address(&addr));
        cache.store_address(&addr).unwrap();
        assert!(!cache.is_empty());
        assert!(cache.has_address(&addr));
    }

    #[test]
    fn delete_address() {
        let db = test_helpers::init_tempdb();
        let mut cache = BootstrapCache::new(db, 1000);
        let addr = crate::random_socket_addr();

        assert!(cache.is_empty());
        assert!(!cache.has_address(&addr));
        cache.store_address(&addr).unwrap();
        assert!(!cache.is_empty());
        assert!(cache.has_address(&addr));
        cache.delete_address(&addr).unwrap();
        assert!(cache.is_empty());
        assert!(!cache.has_address(&addr));
    }

    #[test]
    fn entries() {
        let db = test_helpers::init_tempdb();
        let mut cache = BootstrapCache::new(db, 1000);
        let addr1 = crate::random_socket_addr();
        let addr2 = crate::random_socket_addr();
        cache.store_address(&addr1).unwrap();
        cache.store_address(&addr2).unwrap();

        assert!(set![addr1.ip(), addr2.ip()] == cache.entries().map(|e| e.addr.clone()).collect());
    }
}