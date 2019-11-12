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

use graphlib::Graph;
use account::Balance;
use chrono::{DateTime, Utc};
use hashbrown::{HashSet, HashMap};
use transactions::Tx;
use std::collections::BTreeMap;
use crypto::Hash;

/// Memory pool used to store valid yet not processed
/// transactions.
pub struct Mempool {
    /// Lookup table between transaction hashes
    /// and transaction data.
    tx_lookup: HashMap<Hash, Tx>,

    /// Mapping between transaction hashes and a timestamp
    /// denoting the moment they have been added to the mempool.
    timestamp_lookup: HashMap<Hash, DateTime<Utc>>,

    /// Mapping between timestamps of the moment transactions have
    /// been added to the mempool and the respective transactions
    /// hashes.
    timestamp_reverse_lookup: BTreeMap<DateTime<Utc>, Hash>,

    /// Set containing hashes of transactions that 
    /// are currently orphans.
    orphan_set: HashSet<Hash>,

    /// Mapping between currency hashes and transaction
    /// fees. Note that orphan transactions are not stored
    /// in this map.
    /// 
    /// Each entry in the map is an ordered binary tree 
    /// map between transaction fees and transaction hashes.
    fee_map: HashMap<Hash, BTreeMap<Balance, Hash>>,

    /// Transaction dependency graph.
    dependency_graph: Graph<Hash>,

    /// Vector of preferred currencies. The element at
    /// index 0 in the vector is the first preferred,
    /// the one at index 1 is the second, etc.
    /// 
    /// When choosing transactions to take out of the
    /// mempool, they will be taken in the order of 
    /// preference that is found in this vector, if
    /// there is no preferred currency, they will be
    /// taken out of all available currencies from
    /// the biggest fee to the least.
    preferred_currencies: Vec<Hash>,

    /// Ratio of preferred transaction to include in a ready batch,
    /// for example if 50 preference ratio is given, 50% of the transactions
    /// taken from the mempool in one batch will be based on the preference
    /// options, the rest will be taken from each stored currency equally 
    /// from the biggest fee to the lowest.
    /// 
    /// Must be a number between 50 and 100.
    preference_ratio: u8,

    /// The maximum amount of transactions that the
    /// mempool is allowed to store.
    max_size: u64,
}

impl Mempool {
    pub fn new(
        max_size: u64, 
        preferred_currencies: Vec<Hash>,
        preference_ratio: u8,
    ) -> Mempool {
        if preference_ratio < 50 || preference_ratio > 100 {
            panic!(format!("Invalid preference ratio! Expected a number between 50 and 100! Got: {}", preference_ratio));
        }

        Mempool {
            tx_lookup: HashMap::new(),
            timestamp_lookup: HashMap::new(),
            fee_map: HashMap::new(),
            orphan_set: HashSet::new(),
            dependency_graph: Graph::new(),
            timestamp_reverse_lookup: BTreeMap::new(),
            max_size,
            preferred_currencies,
            preference_ratio,
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