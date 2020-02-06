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
use chain::{PowChainRef, PowChainState, MAX_TX_SET_SIZE};
use chain::types::StateInterface;
use account::{NormalAddress, Address, Balance};
use chrono::{DateTime, Utc};
use hashbrown::{HashSet, HashMap};
use transactions::Tx;
use std::collections::{VecDeque, BTreeMap};
use patricia_trie::{TrieDB, Trie};
use persistence::{DbHasher, Codec};
use crypto::{ShortHash, Hash};
use rand::Rng;
use std::sync::Arc;

/// How far into the future a transaction can be 
/// in order to be accepted. 
const FUTURE_LIMIT: u64 = 10;

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
    fee_map: HashMap<ShortHash, BTreeMap<Balance, VecDeque<ShortHash>>>,

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

impl Mempool {
    pub fn new(
        chain_ref: PowChainRef,
        max_size: u32, 
        preferred_currencies: Vec<ShortHash>,
        preference_ratio: u8,
    ) -> Mempool {
        if preference_ratio < 50 || preference_ratio > 100 {
            panic!(format!("Invalid preference ratio! Expected a number between 50 and 100! Got: {}", preference_ratio));
        }

        Mempool {
            tx_lookup: HashMap::new(),
            timestamp_lookup: HashMap::new(),
            fee_map: HashMap::new(),
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

    /// Removes the transaction with the given `Hash` from the 
    /// mempool and returns it. Returns `None` if there is no 
    /// such transaction in the mempool.
    /// 
    /// This operation will orphan any transactions that depend
    /// on the given transaction. Use `Mempool::remove_branch()`
    /// to remove any dependent transactions as well.
    pub fn remove(&mut self, tx_hash: &ShortHash) -> Option<Arc<Tx>> {
        let tx = self.tx_lookup.remove(tx_hash)?;
        let signing_address = tx.creator_signing_address();
        let fee = tx.fee();
        let fee_hash = tx.fee_hash();
        let mut remove_fee_map = false;

        // Clean up from address mappings 
        let mut next_address = self.address_mappings.remove(&signing_address)?;

        // Orphan any subsequent transactions
        while let Some(next_signing_address) = self.address_mappings.get(&next_address) {
            let tx_hash = self.address_hash_mappings.get(&next_signing_address).unwrap(); 
            self.address_reverse_mappings.remove(&next_signing_address);
            if !self.orphan_set.remove(&tx_hash) {
                break;
            };
            next_address = next_signing_address.clone();
        }

        self.orphan_set.remove(tx_hash);

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
    pub fn remove_branch(&mut self, tx_hash: &ShortHash) -> Option<Vec<Arc<Tx>>> {
        unimplemented!();
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
        self.address_mappings.insert(tx_signing_addr.clone(), tx_next_addr.clone());
        self.address_hash_mappings.insert(tx_signing_addr, tx_hash.clone());

        // Update orphans
        if !is_orphan {
            self.update_orphans(&tx_next_addr, tx_signing_addr.clone());
        } else {
            if self.address_reverse_mappings.get(&tx_signing_addr).is_some() {
                self.update_orphans(&tx_next_addr, tx_signing_addr.clone());
            } else {
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
    pub fn prune(&mut self) {
        unimplemented!();
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
        let ratio_size_threshold = (self.preference_ratio as f32 / (100 as f32)) as usize * MAX_TX_SET_SIZE;

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

        let fee_currencies: Vec<&ShortHash> = self.fee_map
            .keys()
            .collect();

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
                        .filter(|tx_hash| !self.orphan_set.contains(&tx_hash) && !taken_set.contains(&tx_hash) && !obsolete_set.contains(&tx_hash))
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
            self.remove(obsolete);
        }

        Some(tx_set.tx_set)
    }

    fn get_account_nonce(&self, address: &Address) -> Option<u64> {
        self.chain_ref.get_account_nonce(&address)
    }

    fn validate_tx_on_chain_state(&self, tx: Arc<Tx>) -> bool {
        self.chain_ref.validate_tx(tx)
    }

    fn update_orphans<'a>(&'a mut self, mut cur_addr: &'a NormalAddress, tx_signing_addr: NormalAddress) {
        self.address_reverse_mappings.insert(cur_addr.clone(), tx_signing_addr);

        while let Some(next_addr) = self.address_mappings.get(cur_addr) {
            let cur_hash = self.address_hash_mappings.get(cur_addr).unwrap();
            self.orphan_set.remove(cur_hash);
            self.address_reverse_mappings.insert(next_addr.clone(), cur_addr.clone());
            
            if let Some(tx_hash) = self.address_hash_mappings.get(&next_addr) {
                self.orphan_set.remove(tx_hash);
                cur_addr = next_addr;
            } else {
                break;
            }
        }
    }
}

pub struct TxSet {
    pub(crate) tx_set: Vec<Arc<Tx>>,
    pub(crate) taken_set: HashSet<ShortHash>,
    pub(crate) obsolete_set: HashSet<ShortHash>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;
    use transactions::TestAccount;
    use rand::prelude::*;

    #[test]
    fn append_fails_on_tx_nonce_that_is_less_or_equal_to_account_nonce() {
        let chain_db = test_helpers::init_tempdb();
        let state_db = test_helpers::init_tempdb();
        let chain = chain::init(chain_db, state_db, true);
        let mut mempool = Mempool::new(chain.clone(), 10000, vec![], 80);
        let tx = Arc::new(transactions::send_coins(TestAccount::A, TestAccount::B, 100, 10, 0));

        assert_eq!(mempool.append_tx(tx), Err(MempoolErr::NonceLeq));
    }

    quickcheck! {
        #[cfg(not(windows))]
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

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_3.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&A_5.tx_hash().unwrap().to_short()));
            
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

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_4.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_1.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_5.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_5.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_4.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_4.tx_hash().unwrap().to_short()));
            
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

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_3.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap().to_short()));
            assert!(mempool.timestamp_lookup.contains_key(&C_3.tx_hash().unwrap().to_short()));
            
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

        // fn remove_stress_test() -> bool {
        //     unimplemented!();
        // }

        // fn prune_stress_test() -> bool {
        //     unimplemented!();
        // }
    }
}