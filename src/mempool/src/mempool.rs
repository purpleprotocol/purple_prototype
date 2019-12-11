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

use crate::error::MempoolErr;
use chain::PowChainRef;
use graphlib::{Graph, VertexId};
use account::{Address, Balance};
use chrono::{DateTime, Utc};
use hashbrown::{HashSet, HashMap};
use transactions::Tx;
use std::collections::{VecDeque, BTreeMap};
use crypto::Hash;
use std::sync::Arc;

/// Memory pool used to store valid yet not processed
/// transactions.
pub struct Mempool {
    /// Lookup table between transaction hashes
    /// and transaction data.
    tx_lookup: HashMap<Hash, Arc<Tx>>,

    /// Mapping between transaction hashes and their 
    /// vertex ids in the dependency graph.
    vertex_id_lookup: HashMap<Hash, VertexId>,

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
    fee_map: HashMap<Hash, BTreeMap<Balance, VecDeque<Hash>>>,

    /// Transaction dependency graph.
    dependency_graph: Graph<Hash>,

    /// Mapping between addresses that have issued transactions
    /// which are currently stored in the mempool and the sub-mapping
    /// of transaction nonces and their hashes.
    address_mappings: HashMap<Address, BTreeMap<u64, Hash>>,

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

    /// Reference to the pow chain.
    chain_ref: PowChainRef,
}

impl Mempool {
    pub fn new(
        chain_ref: PowChainRef,
        max_size: u64, 
        preferred_currencies: Vec<Hash>,
        preference_ratio: u8,
    ) -> Mempool {
        if preference_ratio < 50 || preference_ratio > 100 {
            panic!(format!("Invalid preference ratio! Expected a number between 50 and 100! Got: {}", preference_ratio));
        }

        Mempool {
            tx_lookup: HashMap::new(),
            vertex_id_lookup: HashMap::new(),
            timestamp_lookup: HashMap::new(),
            fee_map: HashMap::new(),
            address_mappings: HashMap::new(),
            orphan_set: HashSet::new(),
            dependency_graph: Graph::new(),
            timestamp_reverse_lookup: BTreeMap::new(),
            max_size,
            preferred_currencies,
            preference_ratio,
            chain_ref,
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
    /// 
    /// This operation will orphan any transactions that depend
    /// on the given transaction. Use `Mempool::remove_branch()`
    /// to remove any dependent transactions as well.
    pub fn remove(&mut self, tx_hash: &Hash) -> Option<Arc<Tx>> {
        let tx = self.tx_lookup.remove(tx_hash)?;
        let address = tx.creator_address();
        let nonce = tx.nonce();
        let vertex_id = self.vertex_id_lookup.remove(tx_hash).unwrap();
        let fee = tx.fee();
        let fee_hash = tx.fee_hash();
        let mut remove_fee_map = false;
        let mut remove_nonces_mapping = false;

        // Clean up from address mappings 
        {
            {
                let nonces_mapping = self.address_mappings.get_mut(&address).unwrap(); 
                nonces_mapping.remove(&nonce).unwrap();
            }

            let nonces_mapping = self.address_mappings.get(&address).unwrap(); 

            if nonces_mapping.is_empty() {
                remove_nonces_mapping = true;
            } else {
                // If the removed transaction is not an orphan, we have
                // check if there are any subsequent transactions that 
                // should be orphaned.
                if !self.orphan_set.contains(tx_hash) {
                    // Orphan subsequent transactions if there are any
                    // and they do not directly follow the nonce listed 
                    // in the state.
                    if let Some(account_nonce) = self.get_account_nonce(&address) {
                        if account_nonce > nonce {
                            // Remove any old transactions i.e. 
                            // lower or equal to the account's nonce
                            for (_, tx_hash) in nonces_mapping.range(..nonce) {
                                self.orphan_set.insert(tx_hash.clone());
                            }
                        } else if account_nonce < nonce {
                            // Orphan transactions that follow the removed nonce
                            for (_, tx_hash) in nonces_mapping.range(nonce..) {
                                self.orphan_set.insert(tx_hash.clone());
                            }
                        } else {
                            // Nonces are equal, do nothing
                        }
                    } else {
                        // Orphan transactions that follow the removed nonce
                        for (_, tx_hash) in nonces_mapping.range(nonce..) {
                            self.orphan_set.insert(tx_hash.clone());
                        }
                    }
                }
            }
        }

        self.orphan_set.remove(tx_hash);
        self.dependency_graph.remove(&vertex_id);

        if remove_nonces_mapping {
            self.address_mappings.remove(&address).unwrap();
        }

        // Clean entry from timestamp lookups
        if let Some(timestamp) = self.timestamp_lookup.remove(tx_hash) {
            self.timestamp_reverse_lookup.remove(&timestamp);
        }

        // Clean entry from fee map
        if let Some(fee_map) = self.fee_map.get_mut(&fee_hash) {
            fee_map.remove(&fee);

            // Clean up fee map entry if it's empty
            if fee_map.is_empty() {
                remove_fee_map = true;
            }
        }

        if remove_fee_map {
            self.fee_map.remove(&fee_hash);
        }

        Some(tx)
    }   

    /// Removes the transaction with the given `Hash` from the 
    /// mempool and any dependent transactions and returns them. 
    /// Returns `None` if there is no such transaction in the mempool.
    pub fn remove_branch(&mut self, tx_hash: &Hash) -> Option<Vec<Arc<Tx>>> {
        unimplemented!();
    }

    /// Attempts to append a transaction to the mempool.
    pub fn append_tx(&mut self, tx: Arc<Tx>) -> Result<(), MempoolErr> {
        if self.tx_lookup.len() >= self.max_size as usize {
            return Err(MempoolErr::Full);
        }

        let tx_addr = tx.creator_address();
        let tx_nonce = tx.nonce();
        let tx_hash = tx.tx_hash().unwrap();

        // Check for existence
        if self.exists(&tx_hash) {
            return Err(MempoolErr::AlreadyInMempool);
        }

        // Check for double spends
        let double_spend = {
            if let Some(nonce_mapping) = self.address_mappings.get(&tx_addr) {
                nonce_mapping.get(&tx_nonce).is_some()
            } else {
                false
            }
        };

        if double_spend {
            return Err(MempoolErr::DoubleSpend);
        }

        let tx_fee = tx.fee();
        let tx_fee_cur = tx.fee_hash();
        let timestamp = Utc::now();

        // Place transaction in respective mappings
        self.tx_lookup.insert(tx_hash.clone(), tx.clone());
        self.timestamp_lookup.insert(tx_hash.clone(), timestamp.clone());
        self.timestamp_reverse_lookup.insert(timestamp, tx_hash.clone());
        
        // Place transaction in fee mappings
        if let Some(cur_entry) = self.fee_map.get_mut(&tx_fee_cur) {
            if let Some(fee_entry) = cur_entry.get_mut(&tx_fee) {
                fee_entry.push_back(tx_hash.clone());
            } else {
                let mut fee_entry = VecDeque::new();

                fee_entry.push_back(tx_hash.clone());
                cur_entry.insert(tx_fee, fee_entry);
            }
        } else {
            let mut cur_entry = BTreeMap::new();
            let mut fee_entry = VecDeque::new();

            fee_entry.push_back(tx_hash.clone());
            cur_entry.insert(tx_fee, fee_entry);

            self.fee_map.insert(tx_fee_cur, cur_entry);
        }

        // Place transaction in address mappings
        if let Some(addr_entry) = self.address_mappings.get_mut(&tx_addr) {
            addr_entry.insert(tx_nonce, tx_hash.clone());
        } else {
            let mut addr_entry = BTreeMap::new();
            
            addr_entry.insert(tx_nonce, tx_hash.clone());
            self.address_mappings.insert(tx_addr, addr_entry);
        }

        // Place transaction in the dependency graph
        // TODO: Construct dependency graph structure
        let vertex_id = self.dependency_graph.add_vertex(tx_hash.clone());
        self.vertex_id_lookup.insert(tx_hash, vertex_id);

        Ok(())
    }

    /// Attempts to perform a prune on the transactions stored 
    /// in the memory pool, removing the oldest transactions 
    /// that have the lowest fees. The prune will be performed
    /// only if the mempool is more than 80% full or if there
    /// are any past transactions found i.e. transactions with
    /// nonces that are lower than the current creator's nonce.
    /// 
    /// This operation is idempotent.
    pub fn prune(&mut self) {
        unimplemented!();
    }

    /// Attempts to retrieve a number of valid transactions from
    /// the mempool. The resulting transaction list will be in a
    /// canonical ordering. Returns `None` if there are no valid
    /// transactions in the mempool.
    pub fn take(&mut self, count: usize) -> Option<Vec<Arc<Tx>>> {
        if self.tx_lookup.is_empty() {
            return None;
        }

        unimplemented!();
    }

    fn get_account_nonce(&self, address: &Address) -> Option<u64> {
        // TODO: Avoid this as it clones the whole state. A better
        // option would be to lock on read position on the chain
        // and query the state without cloning.
        let chain_state = self.chain_ref.canonical_tip_state(); 
        chain_state.get_account_nonce(&address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    // quickcheck! {
    //     fn append_stress_test() -> bool {
    //         unimplemented!();
    //     }

    //     fn remove_stress_test() -> bool {
    //         unimplemented!();
    //     }

    //     fn prune_stress_test() -> bool {
    //         unimplemented!();
    //     }
    // }
}