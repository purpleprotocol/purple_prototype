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
use crypto::Hash;
use std::net::SocketAddr;

/// The key to the main bootstrap cache entry
const BOOTSTRAP_CACHE_PREFIX: &'static [u8] = b"bootstrap_cache";

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

    /// Stores the given address in the bootstrap cache.
    pub fn store_address(&self, addr: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    /// Deletes the entry with the ip of the given address from the bootstrap cache, if found.
    pub fn delete_address(&self, addr: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    /// Returns an iterator over the entries in the bootstrap cache.
    pub fn entries(&self) -> Box<dyn Iterator<Item = &BootstrapCacheEntry>> {
        unimplemented!();
    }

    /// Return true if there are no entries stored in the bootstrap cache
    pub fn is_empty(&self) -> bool {
        unimplemented!();
    }
}