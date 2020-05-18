/*
  Copyright (C) 2018-2020 The Purple Core Developers.
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

#![allow(non_snake_case)]

use crate::error::MempoolErr;
use account::{Address, Balance, NormalAddress};
use chain::types::StateInterface;
use chain::{PowChainRef, PowChainState};
use chrono::{DateTime, Utc};
use constants::*;
use crypto::{Hash, ShortHash};
use hashbrown::{HashMap, HashSet};
use patricia_trie::{Trie, TrieDB};
use persistence::{Codec, DbHasher};
use rand::Rng;
use rust_decimal::Decimal;
use std::collections::{BTreeMap, VecDeque};
use transactions::Tx;
use triomphe::Arc;

/// Memory pool used to store valid yet not processed
/// transactions.
pub struct Mempool {
    /// Lookup table between transaction hashes
    /// and transaction data.
    tx_lookup: HashMap<ShortHash, Arc<Tx>>,

    /// Mapping between transaction hashes and a timestamp
    /// denoting the moment they have been added to the mempool.
    timestamp_lookup: HashMap<ShortHash, DateTime<Utc>>,

    /// Mapping between timestamps of the moment transactions have
    /// been added to the mempool and the respective transactions
    /// hashes.
    timestamp_reverse_lookup: BTreeMap<DateTime<Utc>, ShortHash>,

    /// Set containing hashes of transactions that
    /// are currently orphans.
    orphan_set: HashSet<ShortHash>,

    /// Mapping between currency hashes and transaction
    /// fees. Note that orphan transactions are not stored
    /// in this map.
    ///
    /// Each entry in the map is an ordered binary tree
    /// map between transaction fees and transaction hashes.
    fee_map: HashMap<ShortHash, BTreeMap<Balance, Vec<ShortHash>>>, // TODO: Change Vec to HashSet

    // Mapping between a weight and all the transactions having
    // that specific weight.
    fee_weight_map: BTreeMap<Balance, HashSet<ShortHash>>,

    // Mapping between transaction hash and the weight of it.
    fee_weight_reverse_map: HashMap<ShortHash, Balance>,

    /// Mapping between signing addresses that have issued
    /// transactions which are currently stored in the mempool
    /// and their next addresses.
    address_mappings: HashMap<NormalAddress, NormalAddress>,

    /// Mapping between signing addresses and their previous
    /// signing addresses. Note that this does not contain orphan
    /// entries.
    address_reverse_mappings: HashMap<NormalAddress, NormalAddress>,

    /// Mapping between signing addresses and their transaction hashes.
    address_hash_mappings: HashMap<NormalAddress, ShortHash>,

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
    preferred_currencies: Vec<ShortHash>,

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
    max_size: u32,

    /// Reference to the pow chain.
    chain_ref: PowChainRef,

    /// Cache set of next transactions to be added to a block.
    ///
    /// TODO: Make this a queue of sets and cache subsequent
    /// tx sets as well.
    next_tx_set_cache: Option<TxSet>,
}

pub struct TxSet {
    pub(crate) tx_set: Vec<Arc<Tx>>,
    pub(crate) taken_set: HashSet<ShortHash>,
    pub(crate) obsolete_set: HashSet<ShortHash>,
}

impl Mempool {
    pub fn new(
        chain_ref: PowChainRef,
        max_size: u32,
        preferred_currencies: Vec<ShortHash>,
        preference_ratio: u8,
    ) -> Mempool {
        if preference_ratio < 50 || preference_ratio > 100 {
            panic!(format!(
                "Invalid preference ratio! Expected a number between 50 and 100! Got: {}",
                preference_ratio
            ));
        }

        Mempool {
            tx_lookup: HashMap::new(),
            timestamp_lookup: HashMap::new(),
            fee_map: HashMap::new(),
            fee_weight_map: BTreeMap::new(),
            fee_weight_reverse_map: HashMap::new(),
            address_mappings: HashMap::new(),
            address_reverse_mappings: HashMap::new(),
            address_hash_mappings: HashMap::new(),
            orphan_set: HashSet::new(),
            timestamp_reverse_lookup: BTreeMap::new(),
            max_size,
            preferred_currencies,
            preference_ratio,
            chain_ref,
            next_tx_set_cache: None,
        }
    }

    /// Returns `true` if there is an existing transaction with
    /// the given `Hash` in the mempool.
    pub fn exists(&self, tx_hash: &ShortHash) -> bool {
        self.tx_lookup.get(tx_hash).is_some()
    }

    /// Returns the number of transactions in the mempool.
    pub fn count(&self) -> usize {
        self.tx_lookup.len()
    }

    /// Removes the transaction with the given `Hash` from the
    /// mempool and returns it. Returns `None` if there is no
    /// such transaction in the mempool.
    ///
    /// This operation will not remove the subsequent transactions
    /// Use `Mempool::remove_branch()` to remove any dependent
    /// transactions as well.
    fn remove_internal(&mut self, tx_hash: &ShortHash) -> Option<Arc<Tx>> {
        if cfg!(test) {
            println!("DEBUG REMOVED TX {}.", tx_hash);
        }

        // Clean up from tx_lookup
        let tx = self.tx_lookup.remove(tx_hash)?;
        let signing_address = tx.creator_signing_address();

        // Clean up from address mappings
        self.address_mappings.remove(&signing_address);
        self.address_hash_mappings.remove(&signing_address);
        self.address_reverse_mappings.remove(&signing_address);

        // Clean up from orphans if still there
        self.orphan_set.remove(tx_hash);

        // Clean entry from timestamp lookups
        if let Some(timestamp) = self.timestamp_lookup.remove(tx_hash) {
            self.timestamp_reverse_lookup.remove(&timestamp);
        }

        let fee = tx.fee();
        let fee_hash = tx.fee_hash();
        let mut remove_fee_entry = false;
        let mut remove_fee_map = false;

        // Clean entry from fee map
        if let Some(fee_map) = self.fee_map.get_mut(&fee_hash) {
            if let Some(fee_entry) = fee_map.get_mut(&fee) {
                if let Some(index) = fee_entry.iter().position(|hash| hash == tx_hash) {
                    // If found in the queue, remove transaction hash
                    fee_entry.remove(index);
                }

                // Clean up fee entry if no hashes belong to this fee
                if fee_entry.is_empty() {
                    remove_fee_entry = true;
                }
            }

            if remove_fee_entry {
                fee_map.remove(&fee);
            }

            // Clean up fee map entry if it's empty
            if fee_map.is_empty() {
                remove_fee_map = true;
            }
        }

        if remove_fee_map {
            self.fee_map.remove(&fee_hash);
        }

        // Remove the fee weight information as well
        if let Some(balance) = self.fee_weight_reverse_map.remove(tx_hash) {
            if let Some(set) = self.fee_weight_map.get_mut(&balance) {
                set.remove(tx_hash);
            }
        }

        Some(tx)
    }

    /// Removes the transaction with the given `Hash` from the
    /// mempool and any dependent transactions and returns them.
    /// Returns `None` if there is no such transaction in the mempool.
    pub fn remove_branch(&mut self, tx_hash: &ShortHash) -> Option<Vec<Arc<Tx>>> {
        if cfg!(test) {
            println!("DEBUG BRANCH REMOVED TX {}.", tx_hash);
        }

        if self.tx_lookup.len() == 0 {
            return None;
        }

        // Get the current transaction, return None if doesn't exist
        let tx = self.tx_lookup.get(tx_hash)?;
        let mut signing_address = tx.creator_signing_address();

        let mut to_remove: Vec<ShortHash> = vec![*tx_hash];
        let mut res: Vec<Arc<Tx>> = Vec::new();
        // Search the subsequent transactions and mark them to be removed
        while let Some(next_signing_address) = self.address_mappings.get(&signing_address) {
            if let Some(tx_hash) = self.address_hash_mappings.get(&next_signing_address) {
                to_remove.push(*tx_hash);
                signing_address = next_signing_address.clone();
            } else {
                break;
            }
        }

        // Remove transactions and store them
        for hash in to_remove {
            if let Some(tx_removed) = self.remove_internal(&hash) {
                res.push(tx_removed);
            }
        }

        Some(res)
    }

    /// Attempts to append a transaction to the mempool.
    pub fn append_tx(&mut self, tx: Arc<Tx>) -> Result<(), MempoolErr> {
        if cfg!(test) {
            println!("DEBUG APPENDED TX: {:?}", tx);
        }

        if self.tx_lookup.len() >= self.max_size as usize {
            return Err(MempoolErr::Full);
        }

        let tx_signing_addr = tx.creator_signing_address();
        let tx_next_addr = tx.next_address();
        let tx_nonce = tx.nonce();
        let tx_hash = tx.tx_hash().unwrap().to_short();
        let mut is_orphan = true;

        // Check for existence
        if self.exists(&tx_hash) {
            return Err(MempoolErr::AlreadyInMempool);
        }

        // Check for double spends
        if self.address_mappings.get(&tx_signing_addr).is_some() {
            return Err(MempoolErr::DoubleSpend);
        }

        let account_nonce = self.get_account_nonce(&Address::Normal(tx_signing_addr));

        // Validate transaction against the current state if
        // it directly follows the nonce listed in the state.
        if let Some(account_nonce) = account_nonce {
            if tx_nonce > account_nonce + FUTURE_LIMIT {
                return Err(MempoolErr::TooFarIntoFuture);
            }

            // Check that the tx's nonce is greater than the account nonce
            if tx_nonce <= account_nonce {
                return Err(MempoolErr::NonceLeq);
            }

            if tx_nonce == account_nonce + 1 {
                if !self.validate_tx_on_chain_state(tx.clone()) {
                    if cfg!(test) {
                        println!("DEBUG CHAIN STATE VALIDATION FAILED WITH EXISTING ACCOUNT");
                    }
                    return Err(MempoolErr::BadTx);
                }

                is_orphan = false;
            }
        } else {
            if tx_nonce > FUTURE_LIMIT {
                return Err(MempoolErr::TooFarIntoFuture);
            }

            // A transaction nonce can never be 0
            if tx_nonce == 0 {
                return Err(MempoolErr::NonceLeq);
            }

            if tx_nonce == 1 {
                if !self.validate_tx_on_chain_state(tx.clone()) {
                    if cfg!(test) {
                        println!("DEBUG CHAIN STATE VALIDATION FAILED WITH FIRST NONCE");
                    }
                    return Err(MempoolErr::BadTx);
                }

                is_orphan = false;
            }
        }

        let tx_fee = tx.fee();
        let tx_fee_cur = tx.fee_hash();
        let timestamp = Utc::now();

        // Place transaction in respective mappings
        self.tx_lookup.insert(tx_hash.clone(), tx.clone());
        self.timestamp_lookup
            .insert(tx_hash.clone(), timestamp.clone());
        self.timestamp_reverse_lookup
            .insert(timestamp, tx_hash.clone());

        // Place transaction in fee mappings
        if let Some(cur_entry) = self.fee_map.get_mut(&tx_fee_cur) {
            if let Some(fee_entry) = cur_entry.get_mut(&tx_fee) {
                fee_entry.push(tx_hash.clone());
            } else {
                let mut fee_entry = Vec::new();

                fee_entry.push(tx_hash.clone());
                cur_entry.insert(tx_fee, fee_entry);
            }
        } else {
            let mut cur_entry = BTreeMap::new();
            let mut fee_entry = Vec::new();

            fee_entry.push(tx_hash.clone());
            cur_entry.insert(tx_fee, fee_entry);

            self.fee_map.insert(tx_fee_cur, cur_entry);
        }

        // Place transaction in address mappings
        self.address_mappings
            .insert(tx_signing_addr.clone(), tx_next_addr.clone());
        self.address_hash_mappings
            .insert(tx_signing_addr, tx_hash.clone());

        // Update orphans
        if !is_orphan {
            // First update the fee weight of the current tx
            self.update_fee_weight(tx);
            if let Some(moved) = self.update_orphans(&tx_next_addr, tx_signing_addr.clone()) {
                // Finally, update fee weights for the entities which are not orphans anymore
                for tx_hash_mov in moved {
                    // TODO: change clone
                    let tx_mov = self.tx_lookup.get(&tx_hash_mov).unwrap().clone();
                    self.update_fee_weight(tx_mov);
                }
            }
        } else {
            if self
                .address_reverse_mappings
                .get(&tx_signing_addr)
                .is_some()
            {
                // First update the fee weight of the current tx
                self.update_fee_weight(tx);
                if let Some(moved) = self.update_orphans(&tx_next_addr, tx_signing_addr.clone()) {
                    // Finally, update fee weights for the entities which are not orphans anymore
                    for tx_hash_mov in moved {
                        // TODO: change clone
                        let tx_mov = self.tx_lookup.get(&tx_hash_mov).unwrap().clone();
                        self.update_fee_weight(tx_mov);
                    }
                }
            } else {
                // No fee weight update needed
                self.orphan_set.insert(tx_hash);
            };
        }

        Ok(())
    }

    /// Attempts to perform a prune on the transactions stored
    /// in the memory pool, removing the oldest transactions
    /// that have the lowest fees. The prune will be performed
    /// only if the mempool is more than 80% full.
    ///
    /// This operation is idempotent.
    pub fn prune(&mut self) -> Option<usize> {
        // If the threshold is not exceeded, prune operation will not be performed
        let mut items_to_prune = self.count() as u32 - (self.max_size * PRUNE_THRESHOLD / 100);
        if items_to_prune < 1 {
            return None;
        }
        let mut pruned: usize = items_to_prune.clone() as usize;
        let mut reached_max: bool = false;

        let mut tx_to_remove: Vec<ShortHash> = Vec::new();
        let mut balance_to_clean: Vec<Balance> = Vec::new();

        // Iterate the fee_weight_map starting from the lowest balance
        // to the highest one
        for (balance, next_set) in self.fee_weight_map.iter() {
            for tx_hash in next_set.iter() {
                tx_to_remove.push(tx_hash.clone());

                // Decrease the items remaining to remove
                items_to_prune -= 1;
                if items_to_prune == 0 {
                    reached_max = true;
                    break;
                }
            }

            // Break if collected enough transactions
            if reached_max {
                break;
            }

            // Mark the balance to be removed
            balance_to_clean.push(*balance);
        }

        // Proceed with transactions removal
        for tx_hash in tx_to_remove {
            self.remove_branch(&tx_hash);
        }

        for balance in balance_to_clean {
            self.fee_weight_map.remove(&balance);
        }

        Some(pruned)

        // TODO: mark tx set for recalculation
    }

    /// Attempts to calculate a next transaction set that is to be
    /// appended to a block. This does not remove the transaction
    /// set from the mempool. Use this asynchronously.
    pub fn calculate_next_tx_set(&self) -> Option<TxSet> {
        debug!("Calculating next transaction set...");

        if MAX_TX_SET_SIZE < 2048 {
            panic!("The maximum transaction set size cannot be less than 2kb!");
        }

        if self.tx_lookup.is_empty() {
            debug!("The mempool is empty! No transaction set found!");
            return None;
        }

        // Allocate a capacity of the maximum tx set size divided
        // by the average size of a transaction i.e. ~250 bytes.
        let capacity = MAX_TX_SET_SIZE / 250;

        let mut cur_tx_set_size = 0;
        let mut taken_set: HashSet<ShortHash> = HashSet::with_capacity(capacity);
        let mut obsolete_set: HashSet<ShortHash> = HashSet::with_capacity(capacity);
        let mut tx_set: Vec<Arc<Tx>> = Vec::with_capacity(capacity);
        let mut next_chain_state: PowChainState = self.chain_ref.canonical_tip_state();
        let mut exceeded_max_tx_set_size = false;
        let mut exceeded_ratio_size_threshold = false;

        // TODO: Use decimals here instead of floats
        let ratio_size_threshold =
            (self.preference_ratio as f32 / (100 as f32)) as usize * MAX_TX_SET_SIZE;

        // For each preferred currency take valid
        // transactions with the biggest fees.
        for cur_hash in self.preferred_currencies.iter() {
            if let Some(cur_entry) = self.fee_map.get(&cur_hash) {
                for (_, balance_entry) in cur_entry.iter() {
                    let iter = balance_entry
                        .iter()
                        // Filter orphans
                        .filter(|tx_hash| !self.orphan_set.contains(&tx_hash));

                    for tx_hash in iter {
                        let tx = self.tx_lookup.get(tx_hash).unwrap();
                        let tx_byte_size = tx.byte_size();

                        if cur_tx_set_size + tx_byte_size > ratio_size_threshold {
                            exceeded_ratio_size_threshold = true;
                            break;
                        }

                        if next_chain_state.validate_tx(tx.clone()) {
                            next_chain_state.apply_tx(tx.clone());

                            // Add to set
                            taken_set.insert(tx_hash.clone());
                            tx_set.push(tx.clone());
                            cur_tx_set_size += tx_byte_size;
                        } else {
                            // Mark transaction as obsolete since it failed validation
                            obsolete_set.insert(tx_hash.clone());
                        }
                    }

                    if exceeded_ratio_size_threshold {
                        break;
                    }
                }
            }

            if exceeded_ratio_size_threshold {
                break;
            }
        }

        let fee_currencies: Vec<&ShortHash> = self.fee_map.keys().collect();

        // Hack to break the loop when we cannot fill a tx set
        // to its maximum size but we have exhausted all valid
        // transactions.
        //
        // TODO: Find a better way to do this
        let mut iter_count = 0;

        // Take transactions with the biggest fees
        // from random fee currencies.
        loop {
            let mut rng = rand::thread_rng();
            let cur_idx = rng.gen_range(0, fee_currencies.len());
            let fee_cur_hash = fee_currencies[cur_idx];

            iter_count += 1;

            if let Some(cur_entry) = self.fee_map.get(&fee_cur_hash) {
                for (_, balance_entry) in cur_entry.iter() {
                    let mut iter = balance_entry
                        .iter()
                        // Filter orphans
                        .filter(|tx_hash| {
                            !self.orphan_set.contains(&tx_hash)
                                && !taken_set.contains(&tx_hash)
                                && !obsolete_set.contains(&tx_hash)
                        })
                        .take(1);

                    if let Some(tx_hash) = iter.next() {
                        let tx = self.tx_lookup.get(tx_hash).unwrap();
                        let tx_byte_size = tx.byte_size();

                        if cur_tx_set_size + tx_byte_size > MAX_TX_SET_SIZE {
                            exceeded_max_tx_set_size = true;
                            break;
                        }

                        if next_chain_state.validate_tx(tx.clone()) {
                            next_chain_state.apply_tx(tx.clone());

                            // Add to set
                            taken_set.insert(tx_hash.clone());
                            tx_set.push(tx.clone());
                            cur_tx_set_size += tx_byte_size;
                            iter_count = 0;
                            break;
                        } else {
                            // Mark transaction as obsolete since it failed validation
                            obsolete_set.insert(tx_hash.clone());
                        }
                    }
                }
            }

            if exceeded_max_tx_set_size || iter_count >= 20 {
                break;
            }
        }

        if tx_set.is_empty() {
            return None;
        }

        Some(TxSet {
            tx_set,
            taken_set,
            obsolete_set,
        })
    }

    pub fn has_ready_tx_set(&self) -> bool {
        self.next_tx_set_cache.is_some()
    }

    /// Caches a tx set to be taken out of the mempool. Use this asynchronously.
    pub fn cache_next_tx_set(&mut self, tx_set: TxSet) -> Result<(), MempoolErr> {
        if self.has_ready_tx_set() {
            return Err(MempoolErr::AlreadyHasTxSet);
        }

        self.next_tx_set_cache = Some(tx_set);
        Ok(())
    }

    /// Attempts to retrieve a set of valid transactions from
    /// the mempool. The resulting transaction list will be in a
    /// canonical ordering. Returns `None` if there are no valid
    /// transactions in the mempool.
    pub fn take(&mut self) -> Option<Vec<Arc<Tx>>> {
        if self.tx_lookup.is_empty() {
            return None;
        }

        let tx_set = self.next_tx_set_cache.take()?;

        // Remove obsolete transactions
        for obsolete in tx_set.obsolete_set.iter() {
            self.remove_internal(obsolete);
        }

        Some(tx_set.tx_set)
    }

    fn get_account_nonce(&self, address: &Address) -> Option<u64> {
        self.chain_ref.get_account_nonce(&address)
    }

    fn validate_tx_on_chain_state(&self, tx: Arc<Tx>) -> bool {
        self.chain_ref.validate_tx(tx)
    }

    fn update_orphans<'a>(
        &'a mut self,
        mut cur_addr: &'a NormalAddress,
        tx_signing_addr: NormalAddress,
    ) -> Option<Vec<ShortHash>> {
        let mut moved: Vec<ShortHash> = Vec::new();
        self.address_reverse_mappings
            .insert(cur_addr.clone(), tx_signing_addr);

        while let Some(next_addr) = self.address_mappings.get(cur_addr) {
            let cur_hash = self.address_hash_mappings.get(cur_addr).unwrap();
            if self.orphan_set.remove(cur_hash) {
                // If removed means that transaction is not orphan anymore, add to moved
                moved.push(cur_hash.clone());
            }
            self.address_reverse_mappings
                .insert(next_addr.clone(), cur_addr.clone());

            if let Some(tx_hash) = self.address_hash_mappings.get(&next_addr) {
                if self.orphan_set.remove(tx_hash) {
                    // If removed means that transaction is not orphan anymore, add to moved
                    moved.push(tx_hash.clone());
                }
                cur_addr = next_addr;
            } else {
                break;
            }
        }

        if moved.len() == 0 {
            None
        } else {
            Some(moved)
        }
    }

    // Computes the fee weight for a transaction and updates
    // the fee weight for parent transactions based on proper fee
    // and subsequent fees
    fn update_fee_weight(&mut self, tx: Arc<Tx>) {
        let fee_hash = tx.fee_hash();
        let tx_hash = tx.tx_hash().unwrap().to_short();
        let tx_fee = tx.fee().clone();

        let mut cur_weight: Balance = tx_fee.clone();
        let mut signing_address = tx.creator_signing_address();

        // Get the first subsequent transaction and sum up its weight
        // (it already contains the weights of the subsequent transactions)
        if let Some(next_signing_address) = self.address_mappings.get(&signing_address) {
            if let Some(tx_hash) = self.address_hash_mappings.get(next_signing_address) {
                if let Some(balance) = self.fee_weight_reverse_map.get(tx_hash) {
                    cur_weight += balance.clone();
                }
            }
        }

        // Store the weight of the actual transaction
        self.store_fee_weight_info(cur_weight.clone(), tx_hash.clone());

        // Store it in the reverse map as well
        self.fee_weight_reverse_map
            .insert(tx_hash.clone(), cur_weight);

        // Update the weights for the parent transactions
        while let Some(previous_signing_address) =
            self.address_reverse_mappings.get(&signing_address)
        {
            if let Some(tx_hash) = self.address_hash_mappings.get(&previous_signing_address) {
                // Get previous transaction fee weight
                let mut tx_weight = self.fee_weight_reverse_map.get_mut(tx_hash).unwrap();

                // Remove transaction from set
                let tx_set = self.fee_weight_map.get_mut(&tx_weight).unwrap();
                if tx_set.remove(tx_hash) {
                    if tx_set.is_empty() {
                        self.fee_weight_map.remove(&tx_weight);
                    }
                } else {
                    // This part should be unreachable
                    panic!("Transaction set not found. [unreachable code]");
                }
                // Update previous transaction fee_weight
                *tx_weight += tx_fee;
                // Prepare for next previous transaction
                signing_address = previous_signing_address.clone();

                // Store the weight of the previous transaction
                let tx_h = tx_hash.clone();
                let tx_w = tx_weight.clone();
                self.store_fee_weight_info(tx_w, tx_h);
            } else {
                break;
            }
        }
    }

    fn store_fee_weight_info(&mut self, weight: Balance, tx_hash: ShortHash) {
        // Store the weight of the actual transaction
        if let Some(balance) = self.fee_weight_map.get_mut(&weight) {
            balance.insert(tx_hash.clone());
        } else {
            // Prepare the collection for this weight if doesn't exists
            // and add the tx_hash to it
            let mut transactions = HashSet::new();
            transactions.insert(tx_hash.clone());
            self.fee_weight_map.insert(weight, transactions);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;
    use rand::prelude::*;
    use transactions::TestAccount;

    #[test]
    fn append_fails_on_tx_nonce_that_is_less_or_equal_to_account_nonce() {
        let chain_db = test_helpers::init_tempdb();
        let state_db = test_helpers::init_tempdb();
        let chain = chain::init(chain_db, state_db, true);
        let mut mempool = Mempool::new(chain.clone(), 10000, vec![], 80);
        let tx = Arc::new(transactions::send_coins(
            TestAccount::A,
            TestAccount::B,
            100,
            10,
            0,
        ));

        assert_eq!(mempool.append_tx(tx), Err(MempoolErr::NonceLeq));
    }

    #[test]
    fn iter_over_b_tree_map_orders_by_key_for_balance() {
        let mut tree: BTreeMap<Balance, &'static str> = BTreeMap::new();

        let b1: Balance = Balance::zero();
        let b2: Balance = Balance::from_u64(1000);
        let b3: Balance = Balance::from_u64(10);
        let b4: Balance = Balance::from_u64(100);
        let b5: Balance = Balance::from_u64(1);
        let b6: Balance = Balance::from_u64(10);
        let b7: Balance = Balance::from_u64(100000);
        let b8: Balance = Balance::from_u64(1000);
        let b9: Balance = Balance::from_u64(10);
        let b10: Balance = Balance::from_u64(1);

        // Append
        tree.insert(b1, "b1");
        tree.insert(b2, "b2");
        tree.insert(b3, "b3");
        tree.insert(b4, "b4");
        tree.insert(b5, "b5");
        tree.insert(b6, "b6");
        tree.insert(b7, "b7");
        tree.insert(b8, "b8");
        tree.insert(b9, "b9");
        tree.insert(b10, "b10");

        // Check
        let mut prev_key: Balance = Balance::zero();
        for (key, val) in tree.iter() {
            assert!(prev_key <= *key);
            prev_key = *key;
        }
    }

    #[test]
    fn iter_over_b_tree_map_orders_by_key_for_date_time() {
        let mut tree: BTreeMap<DateTime<Utc>, &'static str> = BTreeMap::new();
        let mut t_ref: DateTime<Utc> = Utc::now();

        let t1: DateTime<Utc> = Utc::now();
        let t2: DateTime<Utc> = Utc::now();
        let t3: DateTime<Utc> = Utc::now();
        let t4: DateTime<Utc> = Utc::now();
        let t5: DateTime<Utc> = Utc::now();
        let t6: DateTime<Utc> = Utc::now();
        let t7: DateTime<Utc> = Utc::now();
        let t8: DateTime<Utc> = Utc::now();
        let t9: DateTime<Utc> = Utc::now();
        let t10: DateTime<Utc> = Utc::now();

        // Append
        tree.insert(t9, "t9");
        tree.insert(t2, "t2");
        tree.insert(t3, "t3");
        tree.insert(t6, "t6");
        tree.insert(t10, "t10");
        tree.insert(t1, "t1");
        tree.insert(t5, "t5");
        tree.insert(t4, "t4");
        tree.insert(t8, "t8");
        tree.insert(t7, "t7");

        // Check
        for (key, val) in tree.iter() {
            assert!(t_ref <= *key);
            t_ref = *key;
        }
    }

    quickcheck! {
        /// Append a set of transactions in 3 stages, checking
        /// the state of the mempool after each stage. Each stage's
        /// transactions are shuffled such that regardless of the
        /// order in which they are appended, they will yield the
        /// same state.
        ///
        /// We use only `Send` transactions from 3 different accounts
        /// A, B and C.
        fn append_stress_test() -> bool {
            let chain_db = test_helpers::init_tempdb();
            let state_db = test_helpers::init_tempdb();
            let chain = chain::init(chain_db, state_db, true);
            let mut mempool = Mempool::new(chain.clone(), 10000, vec![], 80);
            let cur_hash = crypto::hash_slice(transactions::MAIN_CUR_NAME).to_short();

            // Transactions from account A
            let A_1 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 1));
            let A_2 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::C, 100, 5, 2));
            let A_3 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 150, 10, 3));
            let A_4 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 10, 10, 4));
            let A_5 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::C, 100, 10, 5));

            // Transactions from account B
            let B_1 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::C, 100, 10, 1));
            let B_2 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 5, 2));
            let B_3 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::C, 150, 10, 3));
            let B_4 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::C, 10, 10, 4));
            let B_5 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 5));

            // Transactions from account C
            let C_1 = Arc::new(transactions::send_coins(TestAccount::C, TestAccount::B, 100, 10, 1));
            let C_2 = Arc::new(transactions::send_coins(TestAccount::C, TestAccount::A, 100, 5, 2));
            let C_3 = Arc::new(transactions::send_coins(TestAccount::C, TestAccount::B, 150, 10, 3));
            let C_4 = Arc::new(transactions::send_coins(TestAccount::C, TestAccount::B, 10, 10, 4));
            let C_5 = Arc::new(transactions::send_coins(TestAccount::C, TestAccount::A, 100, 10, 5));

            let mut stage_1 = vec![A_1.clone(), A_2.clone(), B_2.clone(), C_1.clone(), C_3.clone(), A_5.clone()];
            let mut stage_2 = vec![A_4.clone(), B_1.clone(), B_5.clone(), C_5.clone(), C_4.clone(), B_4.clone()];
            let mut stage_3 = vec![A_3.clone(), C_2.clone(), B_3.clone()];

            thread_rng().shuffle(&mut stage_1);
            thread_rng().shuffle(&mut stage_2);
            thread_rng().shuffle(&mut stage_3);

            // Append and validate stage 1
            for tx in stage_1.iter() {
                mempool.append_tx(tx.clone()).unwrap();
            }

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&C_1.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&C_3.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));

            // Check next address
            assert_eq!(mempool.address_mappings.get(&A_1.creator_signing_address()).unwrap(), &A_1.next_address());
            assert_eq!(mempool.address_mappings.get(&B_2.creator_signing_address()).unwrap(), &B_2.next_address());
            assert_eq!(mempool.address_mappings.get(&C_1.creator_signing_address()).unwrap(), &C_1.next_address());
            assert_eq!(mempool.address_mappings.get(&C_3.creator_signing_address()).unwrap(), &C_3.next_address());
            assert_eq!(mempool.address_mappings.get(&A_5.creator_signing_address()).unwrap(), &A_5.next_address());

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_3.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));

            #[cfg(not(windows))]
            {
                // Check timestamp reverse lookup
                let A_1_ts = mempool.timestamp_lookup.get(&A_1.tx_hash().unwrap().to_short()).unwrap().clone();
                let A_2_ts = mempool.timestamp_lookup.get(&A_2.tx_hash().unwrap().to_short()).unwrap().clone();
                let B_2_ts = mempool.timestamp_lookup.get(&B_2.tx_hash().unwrap().to_short()).unwrap().clone();
                let C_1_ts = mempool.timestamp_lookup.get(&C_1.tx_hash().unwrap().to_short()).unwrap().clone();
                let C_3_ts = mempool.timestamp_lookup.get(&C_3.tx_hash().unwrap().to_short()).unwrap().clone();
                let A_5_ts = mempool.timestamp_lookup.get(&A_5.tx_hash().unwrap().to_short()).unwrap().clone();

                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_1_ts).unwrap(), &A_1.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_2_ts).unwrap(), &A_2.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_2_ts).unwrap(), &B_2.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&C_1_ts).unwrap(), &C_1.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&C_3_ts).unwrap(), &C_3.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_5_ts).unwrap(), &A_5.tx_hash().unwrap().to_short());

                // Check order of timestamps
                let (_, is_valid) = stage_1
                    .iter()
                    .fold((None, true), |(last, is_valid), cur| {
                        if !is_valid {
                            return (None, false);
                        }

                        if last.is_none() {
                            let ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap().to_short()).unwrap().clone();
                            (Some(ts), true)
                        } else {
                            let last = last.unwrap();
                            let cur_ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap().to_short()).unwrap().clone();

                            if last < cur_ts {
                                (Some(cur_ts), true)
                            } else {
                                (None, false)
                            }
                        }
                    });

                assert!(is_valid);
            }

            // Check fee map
            {
                let fee_map = mempool.fee_map.get(&cur_hash).unwrap();

                assert!(fee_map.get(&A_1.fee()).is_some());
                assert!(fee_map.get(&A_2.fee()).is_some());
                assert!(fee_map.get(&C_1.fee()).is_some());
                assert!(fee_map.get(&C_3.fee()).is_some());
                assert!(fee_map.get(&B_2.fee()).is_some());
                assert!(fee_map.get(&A_5.fee()).is_some());
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&C_1.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&C_3.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&A_5.tx_hash().unwrap().to_short()));

            // Append and validate stage 2
            for tx in stage_2.iter() {
                mempool.append_tx(tx.clone()).unwrap();
            }

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&C_5.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&C_4.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));

            // Check next address
            assert_eq!(mempool.address_mappings.get(&A_4.creator_signing_address()).unwrap(), &A_4.next_address());
            assert_eq!(mempool.address_mappings.get(&B_1.creator_signing_address()).unwrap(), &B_1.next_address());
            assert_eq!(mempool.address_mappings.get(&B_5.creator_signing_address()).unwrap(), &B_5.next_address());
            assert_eq!(mempool.address_mappings.get(&C_5.creator_signing_address()).unwrap(), &C_5.next_address());
            assert_eq!(mempool.address_mappings.get(&C_4.creator_signing_address()).unwrap(), &C_4.next_address());
            assert_eq!(mempool.address_mappings.get(&B_4.creator_signing_address()).unwrap(), &B_4.next_address());

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_5.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_4.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));

            #[cfg(not(windows))]
            {
                // Check timestamp reverse lookup
                let A_4_ts = mempool.timestamp_lookup.get(&A_4.tx_hash().unwrap().to_short()).unwrap().clone();
                let B_1_ts = mempool.timestamp_lookup.get(&B_1.tx_hash().unwrap().to_short()).unwrap().clone();
                let B_5_ts = mempool.timestamp_lookup.get(&B_5.tx_hash().unwrap().to_short()).unwrap().clone();
                let C_5_ts = mempool.timestamp_lookup.get(&C_5.tx_hash().unwrap().to_short()).unwrap().clone();
                let C_4_ts = mempool.timestamp_lookup.get(&C_4.tx_hash().unwrap().to_short()).unwrap().clone();
                let B_4_ts = mempool.timestamp_lookup.get(&B_4.tx_hash().unwrap().to_short()).unwrap().clone();

                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_4_ts).unwrap(), &A_4.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_1_ts).unwrap(), &B_1.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_5_ts).unwrap(), &B_5.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&C_5_ts).unwrap(), &C_5.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&C_4_ts).unwrap(), &C_4.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_4_ts).unwrap(), &B_4.tx_hash().unwrap().to_short());

                // Check order of timestamps
                let (_, is_valid) = stage_2
                    .iter()
                    .fold((None, true), |(last, is_valid), cur| {
                        if !is_valid {
                            return (None, false);
                        }

                        if last.is_none() {
                            let ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap().to_short()).unwrap().clone();
                            (Some(ts), true)
                        } else {
                            let last = last.unwrap();
                            let cur_ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap().to_short()).unwrap().clone();

                            if last < cur_ts {
                                (Some(cur_ts), true)
                            } else {
                                (None, false)
                            }
                        }
                    });

                assert!(is_valid);
            }

            // Check fee map
            {
                let fee_map = mempool.fee_map.get(&cur_hash).unwrap();

                assert!(fee_map.get(&A_4.fee()).is_some());
                assert!(fee_map.get(&B_1.fee()).is_some());
                assert!(fee_map.get(&B_5.fee()).is_some());
                assert!(fee_map.get(&C_5.fee()).is_some());
                assert!(fee_map.get(&C_4.fee()).is_some());
                assert!(fee_map.get(&B_4.fee()).is_some());
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&C_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&B_4.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&B_5.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&C_3.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&C_4.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&C_5.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&A_4.tx_hash().unwrap().to_short()));
            assert!(mempool.orphan_set.contains(&A_5.tx_hash().unwrap().to_short()));

            // Append and validate stage 3
            for tx in stage_3.iter() {
                mempool.append_tx(tx.clone()).unwrap();
            }

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&C_3.tx_hash().unwrap().to_short()));

            // Check next address
            assert_eq!(mempool.address_mappings.get(&A_3.creator_signing_address()).unwrap(), &A_3.next_address());
            assert_eq!(mempool.address_mappings.get(&B_2.creator_signing_address()).unwrap(), &B_2.next_address());
            assert_eq!(mempool.address_mappings.get(&C_3.creator_signing_address()).unwrap(), &C_3.next_address());

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_3.tx_hash().unwrap().to_short()));

            #[cfg(not(windows))]
            {
                // Check timestamp reverse lookup
                let A_3_ts = mempool.timestamp_lookup.get(&A_3.tx_hash().unwrap().to_short()).unwrap().clone();
                let B_2_ts = mempool.timestamp_lookup.get(&B_2.tx_hash().unwrap().to_short()).unwrap().clone();
                let C_3_ts = mempool.timestamp_lookup.get(&C_3.tx_hash().unwrap().to_short()).unwrap().clone();

                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_3_ts).unwrap(), &A_3.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_2_ts).unwrap(), &B_2.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&C_3_ts).unwrap(), &C_3.tx_hash().unwrap().to_short());

                // Check order of timestamps
                let (_, is_valid) = stage_3
                    .iter()
                    .fold((None, true), |(last, is_valid), cur| {
                        if !is_valid {
                            return (None, false);
                        }

                        if last.is_none() {
                            let ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap().to_short()).unwrap().clone();
                            (Some(ts), true)
                        } else {
                            let last = last.unwrap();
                            let cur_ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap().to_short()).unwrap().clone();

                            if last < cur_ts {
                                (Some(cur_ts), true)
                            } else {
                                (None, false)
                            }
                        }
                    });

                assert!(is_valid);
            }

            // Check fee map
            {
                let fee_map = mempool.fee_map.get(&cur_hash).unwrap();

                assert!(fee_map.get(&A_3.fee()).is_some());
                assert!(fee_map.get(&B_2.fee()).is_some());
                assert!(fee_map.get(&C_3.fee()).is_some());
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&C_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&C_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&C_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&C_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&C_3.tx_hash().unwrap().to_short()));

            true
        }

        fn remove_branch_stress_test() -> bool {
            let chain_db = test_helpers::init_tempdb();
            let state_db = test_helpers::init_tempdb();
            let chain = chain::init(chain_db, state_db, true);
            let mut mempool = Mempool::new(chain.clone(), 10000, vec![], 80);
            let cur_hash = crypto::hash_slice(transactions::MAIN_CUR_NAME).to_short();

            // Transactions from account A
            let A_1 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 1));
            let A_2 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 5, 2));
            let A_3 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 150, 10, 3));
            let A_4 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 10, 10, 4));
            let A_5 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 5));

            // Transactions from account B
            let B_1 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 1));
            let B_2 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 5, 2));
            let B_3 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 150, 10, 3));
            let B_4 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 10, 10, 4));
            let B_5 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 5));

            mempool.append_tx(A_1.clone());
            mempool.append_tx(A_2.clone());
            mempool.append_tx(A_3.clone());
            mempool.append_tx(A_4.clone());
            mempool.append_tx(A_5.clone());
            mempool.append_tx(B_1.clone());
            mempool.append_tx(B_2.clone());
            mempool.append_tx(B_3.clone());
            mempool.append_tx(B_4.clone());
            mempool.append_tx(B_5.clone());

            // Store timestamps before clean-up
            let A_1_ts = mempool.timestamp_lookup.get(&A_1.tx_hash().unwrap().to_short()).unwrap().clone();
            let A_2_ts = mempool.timestamp_lookup.get(&A_2.tx_hash().unwrap().to_short()).unwrap().clone();
            let A_3_ts = mempool.timestamp_lookup.get(&A_3.tx_hash().unwrap().to_short()).unwrap().clone();
            let A_4_ts = mempool.timestamp_lookup.get(&A_4.tx_hash().unwrap().to_short()).unwrap().clone();
            let A_5_ts = mempool.timestamp_lookup.get(&A_5.tx_hash().unwrap().to_short()).unwrap().clone();
            let B_1_ts = mempool.timestamp_lookup.get(&B_1.tx_hash().unwrap().to_short()).unwrap().clone();
            let B_2_ts = mempool.timestamp_lookup.get(&B_2.tx_hash().unwrap().to_short()).unwrap().clone();
            let B_3_ts = mempool.timestamp_lookup.get(&B_3.tx_hash().unwrap().to_short()).unwrap().clone();
            let B_4_ts = mempool.timestamp_lookup.get(&B_4.tx_hash().unwrap().to_short()).unwrap().clone();
            let B_5_ts = mempool.timestamp_lookup.get(&B_5.tx_hash().unwrap().to_short()).unwrap().clone();

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));

            // Check next address
            assert_eq!(mempool.address_mappings.get(&A_1.creator_signing_address()).unwrap(), &A_1.next_address());
            assert_eq!(mempool.address_mappings.get(&A_2.creator_signing_address()).unwrap(), &A_2.next_address());
            assert_eq!(mempool.address_mappings.get(&A_3.creator_signing_address()).unwrap(), &A_3.next_address());
            assert_eq!(mempool.address_mappings.get(&A_4.creator_signing_address()).unwrap(), &A_4.next_address());
            assert_eq!(mempool.address_mappings.get(&A_5.creator_signing_address()).unwrap(), &A_5.next_address());
            assert_eq!(mempool.address_mappings.get(&B_1.creator_signing_address()).unwrap(), &B_1.next_address());
            assert_eq!(mempool.address_mappings.get(&B_2.creator_signing_address()).unwrap(), &B_2.next_address());
            assert_eq!(mempool.address_mappings.get(&B_3.creator_signing_address()).unwrap(), &B_3.next_address());
            assert_eq!(mempool.address_mappings.get(&B_4.creator_signing_address()).unwrap(), &B_4.next_address());
            assert_eq!(mempool.address_mappings.get(&B_5.creator_signing_address()).unwrap(), &B_5.next_address());

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));

            #[cfg(not(windows))]
            {
                // Check timestamp reverse lookup
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_1_ts).unwrap(), &A_1.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_2_ts).unwrap(), &A_2.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_3_ts).unwrap(), &A_3.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_4_ts).unwrap(), &A_4.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_5_ts).unwrap(), &A_5.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_1_ts).unwrap(), &B_1.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_2_ts).unwrap(), &B_2.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_3_ts).unwrap(), &B_3.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_4_ts).unwrap(), &B_4.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_5_ts).unwrap(), &B_5.tx_hash().unwrap().to_short());
            }

            // Check fee map
            {
                let fee_map = mempool.fee_map.get(&cur_hash).unwrap();

                assert!(fee_map.get(&A_1.fee()).is_some());
                assert!(fee_map.get(&A_2.fee()).is_some());
                assert!(fee_map.get(&A_3.fee()).is_some());
                assert!(fee_map.get(&A_4.fee()).is_some());
                assert!(fee_map.get(&A_5.fee()).is_some());
                assert!(fee_map.get(&B_1.fee()).is_some());
                assert!(fee_map.get(&B_2.fee()).is_some());
                assert!(fee_map.get(&B_3.fee()).is_some());
                assert!(fee_map.get(&B_4.fee()).is_some());
                assert!(fee_map.get(&B_5.fee()).is_some());
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_5.tx_hash().unwrap().to_short()));

            // Remove some transactions
            mempool.remove_branch(&A_3.tx_hash().unwrap().to_short());
            mempool.remove_branch(&B_5.tx_hash().unwrap().to_short());

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_3.tx_hash().unwrap().to_short())); // not
            assert!(!mempool.tx_lookup.contains_key(&A_4.tx_hash().unwrap().to_short())); // not
            assert!(!mempool.tx_lookup.contains_key(&A_5.tx_hash().unwrap().to_short())); // not
            assert!(mempool.tx_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_5.tx_hash().unwrap().to_short())); // not

            // Check next address
            assert_eq!(mempool.address_mappings.get(&A_1.creator_signing_address()).unwrap(), &A_1.next_address());
            assert_eq!(mempool.address_mappings.get(&A_2.creator_signing_address()).unwrap(), &A_2.next_address());
            assert_eq!(mempool.address_mappings.get(&A_3.creator_signing_address()), None); // not
            assert_eq!(mempool.address_mappings.get(&A_4.creator_signing_address()), None); // not
            assert_eq!(mempool.address_mappings.get(&A_5.creator_signing_address()), None); // not
            assert_eq!(mempool.address_mappings.get(&B_1.creator_signing_address()).unwrap(), &B_1.next_address());
            assert_eq!(mempool.address_mappings.get(&B_2.creator_signing_address()).unwrap(), &B_2.next_address());
            assert_eq!(mempool.address_mappings.get(&B_3.creator_signing_address()).unwrap(), &B_3.next_address());
            assert_eq!(mempool.address_mappings.get(&B_4.creator_signing_address()).unwrap(), &B_4.next_address());
            assert_eq!(mempool.address_mappings.get(&B_5.creator_signing_address()), None); // not

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));

            #[cfg(not(windows))]
            {
                // Check timestamp reverse lookup
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_1_ts).unwrap(), &A_1.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_2_ts).unwrap(), &A_2.tx_hash().unwrap().to_short());
                assert!(mempool.timestamp_reverse_lookup.get(&A_3_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_4_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_5_ts).is_none());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_1_ts).unwrap(), &B_1.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_2_ts).unwrap(), &B_2.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_3_ts).unwrap(), &B_3.tx_hash().unwrap().to_short());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_4_ts).unwrap(), &B_4.tx_hash().unwrap().to_short());
                assert!(mempool.timestamp_reverse_lookup.get(&B_5_ts).is_none());
            }

            // Check fee map
            {
                let fee_map = mempool.fee_map.get(&cur_hash).unwrap();

                assert!(fee_map.get(&A_1.fee()).unwrap().contains(&A_1.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&A_2.fee()).unwrap().contains(&A_2.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&A_3.fee()).unwrap().contains(&A_3.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&A_4.fee()).unwrap().contains(&A_4.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&A_5.fee()).unwrap().contains(&A_5.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&B_1.fee()).unwrap().contains(&B_1.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&B_2.fee()).unwrap().contains(&B_2.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&B_3.fee()).unwrap().contains(&B_3.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&B_4.fee()).unwrap().contains(&B_4.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&B_5.fee()).unwrap().contains(&B_5.tx_hash().unwrap().to_short()));
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_5.tx_hash().unwrap().to_short()));

            // Remove some transactions
            mempool.remove_branch(&A_2.tx_hash().unwrap().to_short());
            mempool.remove_branch(&B_2.tx_hash().unwrap().to_short());

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            assert!(mempool.tx_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));

            // Check next address
            assert_eq!(mempool.address_mappings.get(&A_1.creator_signing_address()).unwrap(), &A_1.next_address());
            assert_eq!(mempool.address_mappings.get(&A_2.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&A_3.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&A_4.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&A_5.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_1.creator_signing_address()).unwrap(), &B_1.next_address());
            assert_eq!(mempool.address_mappings.get(&B_2.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_3.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_4.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_5.creator_signing_address()), None);

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));

            #[cfg(not(windows))]
            {
                // Check timestamp reverse lookup
                assert_eq!(mempool.timestamp_reverse_lookup.get(&A_1_ts).unwrap(), &A_1.tx_hash().unwrap().to_short());
                assert!(mempool.timestamp_reverse_lookup.get(&A_2_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_3_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_4_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_5_ts).is_none());
                assert_eq!(mempool.timestamp_reverse_lookup.get(&B_1_ts).unwrap(), &B_1.tx_hash().unwrap().to_short());
                assert!(mempool.timestamp_reverse_lookup.get(&B_2_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_3_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_4_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_5_ts).is_none());
            }

            // Check fee map
            {
                let fee_map = mempool.fee_map.get(&cur_hash).unwrap();

                assert!(fee_map.get(&A_1.fee()).unwrap().contains(&A_1.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&A_2.fee()).is_none()); // A_2 & B_2 removed, both fee = 5 the queue gets removed
                assert!(!fee_map.get(&A_3.fee()).unwrap().contains(&A_3.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&A_4.fee()).unwrap().contains(&A_4.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&A_5.fee()).unwrap().contains(&A_5.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&B_1.fee()).unwrap().contains(&B_1.tx_hash().unwrap().to_short()));
                assert!(fee_map.get(&B_2.fee()).is_none()); // A_2 & B_2 removed, both fee = 5 the queue gets removed
                assert!(!fee_map.get(&B_3.fee()).unwrap().contains(&B_3.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&B_4.fee()).unwrap().contains(&B_4.tx_hash().unwrap().to_short()));
                assert!(!fee_map.get(&B_5.fee()).unwrap().contains(&B_5.tx_hash().unwrap().to_short()));
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_5.tx_hash().unwrap().to_short()));

            // Remove some transactions
            mempool.remove_branch(&A_1.tx_hash().unwrap().to_short());
            mempool.remove_branch(&B_1.tx_hash().unwrap().to_short());

            // Check tx lookup
            assert!(!mempool.tx_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.tx_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));

            // Check next address
            assert_eq!(mempool.address_mappings.get(&A_1.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&A_2.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&A_3.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&A_4.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&A_5.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_1.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_2.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_3.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_4.creator_signing_address()), None);
            assert_eq!(mempool.address_mappings.get(&B_5.creator_signing_address()), None);

            // Check timestamp lookup
            assert!(!mempool.timestamp_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.timestamp_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));

            #[cfg(not(windows))]
            {
                // Check timestamp reverse lookup
                assert!(mempool.timestamp_reverse_lookup.get(&A_1_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_2_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_3_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_4_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&A_5_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_1_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_2_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_3_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_4_ts).is_none());
                assert!(mempool.timestamp_reverse_lookup.get(&B_5_ts).is_none());
            }

            // Check fee map
            {
                // Every transaction has been removed, so the fee map should be empty
                assert_eq!(mempool.fee_map.len(), 0);
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&A_5.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_3.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_4.tx_hash().unwrap().to_short()));
            assert!(!mempool.orphan_set.contains(&B_5.tx_hash().unwrap().to_short()));

            true
        }

        fn prune_stress_test() -> bool {true}

        // println!("A_1 TxHash: {:?}, Fee: {:?}", A_1.clone().tx_hash().unwrap().to_short(), A_1.clone().fee());
        // println!("A_2 TxHash: {:?}, Fee: {:?}", A_2.clone().tx_hash().unwrap().to_short(), A_2.clone().fee());
        // println!("A_3 TxHash: {:?}, Fee: {:?}", A_3.clone().tx_hash().unwrap().to_short(), A_3.clone().fee());
        // println!("A_4 TxHash: {:?}, Fee: {:?}", A_4.clone().tx_hash().unwrap().to_short(), A_4.clone().fee());
        // println!("A_5 TxHash: {:?}, Fee: {:?}", A_5.clone().tx_hash().unwrap().to_short(), A_5.clone().fee());
        // println!("B_1 TxHash: {:?}, Fee: {:?}", B_1.clone().tx_hash().unwrap().to_short(), B_1.clone().fee());
        // println!("B_2 TxHash: {:?}, Fee: {:?}", B_2.clone().tx_hash().unwrap().to_short(), B_2.clone().fee());
        // println!("B_3 TxHash: {:?}, Fee: {:?}", B_3.clone().tx_hash().unwrap().to_short(), B_3.clone().fee());
        // println!("B_4 TxHash: {:?}, Fee: {:?}", B_4.clone().tx_hash().unwrap().to_short(), B_4.clone().fee());
        // println!("B_5 TxHash: {:?}, Fee: {:?}", B_5.clone().tx_hash().unwrap().to_short(), B_5.clone().fee());

        fn it_computes_weight_maps_correctly_on_ordered_insertion() -> bool {
            let chain_db = test_helpers::init_tempdb();
            let state_db = test_helpers::init_tempdb();
            let chain = chain::init(chain_db, state_db, true);
            let mut mempool = Mempool::new(chain.clone(), 10000, vec![], 80);
            let cur_hash = crypto::hash_slice(transactions::MAIN_CUR_NAME).to_short();

            // Transactions from account A
            let A_1 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 1));
            let A_2 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 5, 2));
            let A_3 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 150, 10, 3));
            let A_4 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 10, 20, 4));
            let A_5 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 5));

            // Transactions from account B
            let B_1 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 1));
            let B_2 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 5, 2));
            let B_3 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 150, 10, 3));
            let B_4 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 10, 25, 4));
            let B_5 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 5));

            // Append transactions
            mempool.append_tx(A_1.clone());
            mempool.append_tx(A_2.clone());
            mempool.append_tx(A_3.clone());
            mempool.append_tx(A_4.clone());
            mempool.append_tx(A_5.clone());
            mempool.append_tx(B_1.clone());
            mempool.append_tx(B_2.clone());
            mempool.append_tx(B_3.clone());
            mempool.append_tx(B_4.clone());
            mempool.append_tx(B_5.clone());

            // Proceed with checking
            let tx_count = mempool.count();

            let A1_weight = Balance::from_u64(55);
            let A2_weight = Balance::from_u64(45);
            let A3_weight = Balance::from_u64(40);
            let A4_weight = Balance::from_u64(30);
            let A5_weight = Balance::from_u64(10);
            let B1_weight = Balance::from_u64(60);
            let B2_weight = Balance::from_u64(50);
            let B3_weight = Balance::from_u64(45);
            let B4_weight = Balance::from_u64(35);
            let B5_weight = Balance::from_u64(10);

            // Check reverse map
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_1.tx_hash().unwrap().to_short()).unwrap(), A1_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_2.tx_hash().unwrap().to_short()).unwrap(), A2_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_3.tx_hash().unwrap().to_short()).unwrap(), A3_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_4.tx_hash().unwrap().to_short()).unwrap(), A4_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_5.tx_hash().unwrap().to_short()).unwrap(), A5_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_1.tx_hash().unwrap().to_short()).unwrap(), B1_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_2.tx_hash().unwrap().to_short()).unwrap(), B2_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_3.tx_hash().unwrap().to_short()).unwrap(), B3_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_4.tx_hash().unwrap().to_short()).unwrap(), B4_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_5.tx_hash().unwrap().to_short()).unwrap(), B5_weight);

            // Check weights length
            let mut cnt = 0;
            for (balance, set) in mempool.fee_weight_map {
                cnt += set.len();
            }

            assert_eq!(cnt, tx_count);
            assert_eq!(mempool.fee_weight_reverse_map.len(), tx_count);

            true
        }

        fn it_computes_weight_maps_correctly_on_random_insertion() -> bool {
            let chain_db = test_helpers::init_tempdb();
            let state_db = test_helpers::init_tempdb();
            let chain = chain::init(chain_db, state_db, true);
            let mut mempool = Mempool::new(chain.clone(), 10000, vec![], 80);
            let cur_hash = crypto::hash_slice(transactions::MAIN_CUR_NAME).to_short();

            // Transactions from account A
            let A_1 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 1));
            let A_2 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 5, 2));
            let A_3 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 150, 10, 3));
            let A_4 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 10, 20, 4));
            let A_5 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 5));

            // Transactions from account B
            let B_1 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 1));
            let B_2 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 5, 2));
            let B_3 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 150, 10, 3));
            let B_4 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 10, 25, 4));
            let B_5 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 5));

            mempool.append_tx(B_2.clone());
            mempool.append_tx(A_2.clone());
            mempool.append_tx(B_4.clone());
            mempool.append_tx(B_1.clone());
            mempool.append_tx(A_3.clone());
            mempool.append_tx(A_4.clone());
            mempool.append_tx(A_5.clone());
            mempool.append_tx(B_3.clone());
            mempool.append_tx(B_5.clone());
            mempool.append_tx(A_1.clone());

            // Proceed with checking
            let tx_count = mempool.count();

            let A1_weight = Balance::from_u64(55);
            let A2_weight = Balance::from_u64(45);
            let A3_weight = Balance::from_u64(40);
            let A4_weight = Balance::from_u64(30);
            let A5_weight = Balance::from_u64(10);
            let B1_weight = Balance::from_u64(60);
            let B2_weight = Balance::from_u64(50);
            let B3_weight = Balance::from_u64(45);
            let B4_weight = Balance::from_u64(35);
            let B5_weight = Balance::from_u64(10);

            // Check reverse map
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_1.tx_hash().unwrap().to_short()).unwrap(), A1_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_2.tx_hash().unwrap().to_short()).unwrap(), A2_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_3.tx_hash().unwrap().to_short()).unwrap(), A3_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_4.tx_hash().unwrap().to_short()).unwrap(), A4_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_5.tx_hash().unwrap().to_short()).unwrap(), A5_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_1.tx_hash().unwrap().to_short()).unwrap(), B1_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_2.tx_hash().unwrap().to_short()).unwrap(), B2_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_3.tx_hash().unwrap().to_short()).unwrap(), B3_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_4.tx_hash().unwrap().to_short()).unwrap(), B4_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_5.tx_hash().unwrap().to_short()).unwrap(), B5_weight);

            // Check weights length
            let mut cnt = 0;
            for (balance, set) in mempool.fee_weight_map {
                cnt += set.len();
            }

            assert_eq!(cnt, tx_count);
            assert_eq!(mempool.fee_weight_reverse_map.len(), tx_count);

            true
        }

        fn it_computes_weight_maps_correctly_on_random_insertion_intermediate_checks() -> bool {
            let chain_db = test_helpers::init_tempdb();
            let state_db = test_helpers::init_tempdb();
            let chain = chain::init(chain_db, state_db, true);
            let mut mempool = Mempool::new(chain.clone(), 10000, vec![], 80);
            let cur_hash = crypto::hash_slice(transactions::MAIN_CUR_NAME).to_short();

            // Transactions from account A
            let A_1 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 1));
            let A_2 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 5, 2));
            let A_3 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 150, 10, 3));
            let A_4 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 10, 20, 4));
            let A_5 = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 5));

            // Transactions from account B
            let B_1 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 1));
            let B_2 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 5, 2));
            let B_3 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 150, 10, 3));
            let B_4 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 10, 25, 4));
            let B_5 = Arc::new(transactions::send_coins(TestAccount::B, TestAccount::A, 100, 10, 5));

            let mut check_balance_key = | mempool: &Mempool, pairs: Vec<(Balance, ShortHash)> | -> usize {
                let mut len = 0;

                for (b, hash) in pairs {
                    if let Some(set) = mempool.fee_weight_map.get(&b) {
                        if set.contains(&hash) {
                            len += 1;
                        }
                    }
                }

                len
            };

            mempool.append_tx(B_2.clone());
            // B_2 orphan, no weight
            assert!(mempool.fee_weight_map.is_empty());
            assert!(mempool.fee_weight_reverse_map.is_empty());

            mempool.append_tx(A_2.clone());
            // A_2 orphan, still no weight
            assert!(mempool.fee_weight_map.is_empty());
            assert!(mempool.fee_weight_reverse_map.is_empty());
            mempool.append_tx(B_4.clone());
            // B_4 orphan, still no weight
            assert!(mempool.fee_weight_map.is_empty());
            assert!(mempool.fee_weight_reverse_map.is_empty());

            mempool.append_tx(B_1.clone());
            // B_1 not orphan, also updates B_2 => stored: B_1, B_2
            let check = vec![(Balance::from_u64(15), B_1.tx_hash().unwrap().to_short()), (Balance::from_u64(5), B_2.tx_hash().unwrap().to_short())];
            let cnt = check_balance_key(&mempool, check);
            assert_eq!(cnt, 2);
            assert_eq!(mempool.fee_weight_reverse_map.len(), 2);
            mempool.append_tx(A_3.clone());
            // A_3 orphan => stored: B_1, B_2
            let check = vec![(Balance::from_u64(15), B_1.tx_hash().unwrap().to_short()), (Balance::from_u64(5), B_2.tx_hash().unwrap().to_short())];
            let cnt = check_balance_key(&mempool, check);
            assert_eq!(cnt, 2);
            assert_eq!(mempool.fee_weight_reverse_map.len(), 2);

            mempool.append_tx(A_4.clone());
            // A_4 orphan => stored: B_1, B_2
            let check = vec![(Balance::from_u64(15), B_1.tx_hash().unwrap().to_short()), (Balance::from_u64(5), B_2.tx_hash().unwrap().to_short())];
            let cnt = check_balance_key(&mempool, check);
            assert_eq!(cnt, 2);
            assert_eq!(mempool.fee_weight_reverse_map.len(), 2);

            mempool.append_tx(A_5.clone());
            // A_5 orphan => stored: B_1, B_2
            let check = vec![(Balance::from_u64(15), B_1.tx_hash().unwrap().to_short()), (Balance::from_u64(5), B_2.tx_hash().unwrap().to_short())];
            let cnt = check_balance_key(&mempool, check);
            assert_eq!(cnt, 2);
            assert_eq!(mempool.fee_weight_reverse_map.len(), 2);

            mempool.append_tx(B_3.clone());
            // B_3 not orphan, also updates B_4 => stored B_1, B_2, B_3, B_4
            let check = vec![(Balance::from_u64(50), B_1.tx_hash().unwrap().to_short()), (Balance::from_u64(40), B_2.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(35), B_3.tx_hash().unwrap().to_short()), (Balance::from_u64(25), B_4.tx_hash().unwrap().to_short())];
            let cnt = check_balance_key(&mempool, check);
            assert_eq!(cnt, 4);
            assert_eq!(mempool.fee_weight_reverse_map.len(), 4);

            mempool.append_tx(B_5.clone());
            // B_5 not orphan => stored B_1, B_2, B_3, B_4, B_5
            let check = vec![(Balance::from_u64(60), B_1.tx_hash().unwrap().to_short()), (Balance::from_u64(50), B_2.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(45), B_3.tx_hash().unwrap().to_short()), (Balance::from_u64(35), B_4.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(10), B_5.tx_hash().unwrap().to_short())];
            let cnt = check_balance_key(&mempool, check);
            assert_eq!(cnt, 5);
            assert_eq!(mempool.fee_weight_reverse_map.len(), 5);

            mempool.append_tx(A_1.clone());
            // A_1 not orphan, also updates A_2, A_3, A_4, A_5 => stored A_1, A_2, A_3, A_4, A_5, B_1, B_2, B_3, B_4, B_5
            let check = vec![(Balance::from_u64(55), A_1.tx_hash().unwrap().to_short()), (Balance::from_u64(45), A_2.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(40), A_3.tx_hash().unwrap().to_short()), (Balance::from_u64(30), A_4.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(10), A_5.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(60), B_1.tx_hash().unwrap().to_short()), (Balance::from_u64(50), B_2.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(45), B_3.tx_hash().unwrap().to_short()), (Balance::from_u64(35), B_4.tx_hash().unwrap().to_short()),
                             (Balance::from_u64(10), B_5.tx_hash().unwrap().to_short())];
            let cnt = check_balance_key(&mempool, check);
            assert_eq!(cnt, 10);
            assert_eq!(mempool.fee_weight_reverse_map.len(), 10);

            // Final checks
            let tx_count = mempool.count();

            // Final weights
            let A1_weight = Balance::from_u64(55);
            let A2_weight = Balance::from_u64(45);
            let A3_weight = Balance::from_u64(40);
            let A4_weight = Balance::from_u64(30);
            let A5_weight = Balance::from_u64(10);
            let B1_weight = Balance::from_u64(60);
            let B2_weight = Balance::from_u64(50);
            let B3_weight = Balance::from_u64(45);
            let B4_weight = Balance::from_u64(35);
            let B5_weight = Balance::from_u64(10);

            // Check reverse map
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_1.tx_hash().unwrap().to_short()).unwrap(), A1_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_2.tx_hash().unwrap().to_short()).unwrap(), A2_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_3.tx_hash().unwrap().to_short()).unwrap(), A3_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_4.tx_hash().unwrap().to_short()).unwrap(), A4_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&A_5.tx_hash().unwrap().to_short()).unwrap(), A5_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_1.tx_hash().unwrap().to_short()).unwrap(), B1_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_2.tx_hash().unwrap().to_short()).unwrap(), B2_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_3.tx_hash().unwrap().to_short()).unwrap(), B3_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_4.tx_hash().unwrap().to_short()).unwrap(), B4_weight);
            assert_eq!(*mempool.fee_weight_reverse_map.get(&B_5.tx_hash().unwrap().to_short()).unwrap(), B5_weight);

            // Check weights length
            let mut cnt = 0;
            for (balance, set) in mempool.fee_weight_map {
                cnt += set.len();
            }

            assert_eq!(cnt, tx_count);
            assert_eq!(mempool.fee_weight_reverse_map.len(), tx_count);

            true
        }
    }
}
