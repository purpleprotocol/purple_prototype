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

use hashbrown::HashMap;
use transactions::Tx;
use crypto::Hash;

/// Memory pool used to store yet not processed
/// transactions.
pub struct Mempool {
    /// Lookup table between transaction hashes
    /// and transaction data.
    tx_lookup: HashMap<Hash, Tx>,

    /// The maximum amount of transactions that the
    /// mempool is allowed to store.
    max_size: u32,
}

impl Mempool {
    pub fn new(max_size: u32) -> Mempool {
        Mempool {
            tx_lookup: HashMap::with_capacity(max_size as usize),
            max_size,
        }
    }

    /// Returns `true` if there is an existing transaction with
    /// the given `Hash` in the mempool.
    pub fn exists(&self, tx_hash: &Hash) -> bool {
        self.tx_lookup.get(tx_hash).is_some()
    }

    /// Removes the transaction with the given `Hash` from the 
    /// mempool and returns it. Returns `None` if there is no 
    /// such transaction in the mempool.
    pub fn remove(&mut self, tx_hash: &Hash) -> Option<Tx> {
        self.tx_lookup.remove(tx_hash)
    }
}