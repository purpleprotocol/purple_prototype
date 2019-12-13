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

#![allow(non_snake_case)]

use crate::error::MempoolErr;
use chain::PowChainRef;
use account::{Address, Balance};
use chrono::{DateTime, Utc};
use hashbrown::{HashSet, HashMap};
use transactions::Tx;
use std::collections::{VecDeque, BTreeMap};
use patricia_trie::{TrieDB, Trie};
use persistence::{BlakeDbHasher, Codec};
use crypto::Hash;
use std::sync::Arc;

/// How far into the future a transaction can be 
/// in order to be accepted. If the tx's nonce is
/// greater than the current account's nonce + NONCE_LIMIT
/// it will be rejected.
const NONCE_LIMIT: u64 = 10;

/// Memory pool used to store valid yet not processed
/// transactions.
pub struct Mempool {
    /// Lookup table between transaction hashes
    /// and transaction data.
    tx_lookup: HashMap<Hash, Arc<Tx>>,

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
            timestamp_lookup: HashMap::new(),
            fee_map: HashMap::new(),
            address_mappings: HashMap::new(),
            orphan_set: HashSet::new(),
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
        if cfg!(test) {
            println!("DEBUG APPENDED TX: {:?}", tx);
        }

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

        let account_nonce = self.get_account_nonce(&tx_addr);

        // Validate transaction against the current state if 
        // it directly follows the nonce listed in the state.
        if let Some(account_nonce) = account_nonce {
            if tx_nonce > account_nonce + NONCE_LIMIT {
                return Err(MempoolErr::TooFarIntoFuture);
            }

            if tx_nonce == account_nonce + 1 {
                if !self.validate_tx_on_chain_state(tx.clone()) {
                    if cfg!(test) {
                        println!("DEBUG CHAIN STATE VALIDATION FAILED WITH EXISTING ACCOUNT");
                    }
                    return Err(MempoolErr::BadTx); 
                }
            }
        } else {
            if tx_nonce > NONCE_LIMIT {
                return Err(MempoolErr::TooFarIntoFuture);
            }

            if tx_nonce == 1 {
                if !self.validate_tx_on_chain_state(tx.clone()) {
                    if cfg!(test) {
                        println!("DEBUG CHAIN STATE VALIDATION FAILED WITH FIRST NONCE");
                    }
                   return Err(MempoolErr::BadTx); 
                }
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
        if let Some(addr_entry) = self.address_mappings.get_mut(&tx_addr) {
            addr_entry.insert(tx_nonce, tx_hash.clone());
        } else {
            let mut addr_entry = BTreeMap::new();
            
            addr_entry.insert(tx_nonce, tx_hash.clone());
            self.address_mappings.insert(tx_addr, addr_entry);
        }

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
        self.chain_ref.get_account_nonce(&address)
    }

    fn validate_tx_on_chain_state(&self, tx: Arc<Tx>) -> bool {
        self.chain_ref.validate_tx(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;
    use transactions::TestAccount;
    use rand::prelude::*;

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

            let A_addr = TestAccount::A.to_address();
            let B_addr = TestAccount::B.to_address();
            let C_addr = TestAccount::C.to_address();
            let cur_hash = crypto::hash_slice(transactions::MAIN_CUR_NAME);

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
            assert!(mempool.tx_lookup.contains_key(&A_1.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&A_2.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&C_1.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&C_3.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&A_5.tx_hash().unwrap()));

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_1.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&A_2.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&C_1.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&C_3.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&A_5.tx_hash().unwrap()));
            
            // Check timestamp reverse lookup
            let A_1_ts = mempool.timestamp_lookup.get(&A_1.tx_hash().unwrap()).unwrap().clone();
            let A_2_ts = mempool.timestamp_lookup.get(&A_2.tx_hash().unwrap()).unwrap().clone();
            let B_2_ts = mempool.timestamp_lookup.get(&B_2.tx_hash().unwrap()).unwrap().clone();
            let C_1_ts = mempool.timestamp_lookup.get(&C_1.tx_hash().unwrap()).unwrap().clone();
            let C_3_ts = mempool.timestamp_lookup.get(&C_3.tx_hash().unwrap()).unwrap().clone();
            let A_5_ts = mempool.timestamp_lookup.get(&A_5.tx_hash().unwrap()).unwrap().clone();

            assert_eq!(mempool.timestamp_reverse_lookup.get(&A_1_ts).unwrap(), &A_1.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&A_2_ts).unwrap(), &A_2.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&B_2_ts).unwrap(), &B_2.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&C_1_ts).unwrap(), &C_1.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&C_3_ts).unwrap(), &C_3.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&A_5_ts).unwrap(), &A_5.tx_hash().unwrap());

            // Check order of timestamps
            let (_, is_valid) = stage_1
                .iter()
                .fold((None, true), |(last, is_valid), cur| {
                    if !is_valid {
                        return (None, false);
                    }

                    if last.is_none() {
                        let ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap()).unwrap().clone();
                        (Some(ts), true)
                    } else {
                        let last = last.unwrap();
                        let cur_ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap()).unwrap().clone();

                        if last < cur_ts {
                            (Some(cur_ts), true)
                        } else {
                            (None, false)
                        }
                    }
                });

            assert!(is_valid);

            // Check address mappings
            {
                let A_mappings = mempool.address_mappings.get(&A_addr).unwrap();
                let B_mappings = mempool.address_mappings.get(&B_addr).unwrap();
                let C_mappings = mempool.address_mappings.get(&C_addr).unwrap();

                assert_eq!(A_mappings.get(&A_1.nonce()).unwrap(), &A_1.tx_hash().unwrap());
                assert_eq!(A_mappings.get(&A_2.nonce()).unwrap(), &A_2.tx_hash().unwrap());
                assert_eq!(A_mappings.get(&A_5.nonce()).unwrap(), &A_5.tx_hash().unwrap());
                assert_eq!(B_mappings.get(&B_2.nonce()).unwrap(), &B_2.tx_hash().unwrap());
                assert_eq!(C_mappings.get(&C_1.nonce()).unwrap(), &C_1.tx_hash().unwrap());
                assert_eq!(C_mappings.get(&C_3.nonce()).unwrap(), &C_3.tx_hash().unwrap());
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
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&C_1.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&C_3.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&B_2.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&A_5.tx_hash().unwrap()));

            // Append and validate stage 2
            for tx in stage_2.iter() {
                mempool.append_tx(tx.clone()).unwrap();
            }

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_4.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&B_1.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&B_5.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&C_5.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&C_4.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&B_4.tx_hash().unwrap()));

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_4.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&B_1.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&B_5.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&C_5.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&C_4.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&B_4.tx_hash().unwrap()));
            
            // Check timestamp reverse lookup
            let A_4_ts = mempool.timestamp_lookup.get(&A_4.tx_hash().unwrap()).unwrap().clone();
            let B_1_ts = mempool.timestamp_lookup.get(&B_1.tx_hash().unwrap()).unwrap().clone();
            let B_5_ts = mempool.timestamp_lookup.get(&B_5.tx_hash().unwrap()).unwrap().clone();
            let C_5_ts = mempool.timestamp_lookup.get(&C_5.tx_hash().unwrap()).unwrap().clone();
            let C_4_ts = mempool.timestamp_lookup.get(&C_4.tx_hash().unwrap()).unwrap().clone();
            let B_4_ts = mempool.timestamp_lookup.get(&B_4.tx_hash().unwrap()).unwrap().clone();

            assert_eq!(mempool.timestamp_reverse_lookup.get(&A_4_ts).unwrap(), &A_4.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&B_1_ts).unwrap(), &B_1.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&B_5_ts).unwrap(), &B_5.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&C_5_ts).unwrap(), &C_5.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&C_4_ts).unwrap(), &C_4.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&B_4_ts).unwrap(), &B_4.tx_hash().unwrap());

            // Check order of timestamps
            let (_, is_valid) = stage_2
                .iter()
                .fold((None, true), |(last, is_valid), cur| {
                    if !is_valid {
                        return (None, false);
                    }

                    if last.is_none() {
                        let ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap()).unwrap().clone();
                        (Some(ts), true)
                    } else {
                        let last = last.unwrap();
                        let cur_ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap()).unwrap().clone();

                        if last < cur_ts {
                            (Some(cur_ts), true)
                        } else {
                            (None, false)
                        }
                    }
                });

            assert!(is_valid);

            // Check address mappings
            {
                let A_mappings = mempool.address_mappings.get(&A_addr).unwrap();
                let B_mappings = mempool.address_mappings.get(&B_addr).unwrap();
                let C_mappings = mempool.address_mappings.get(&C_addr).unwrap();

                assert_eq!(A_mappings.get(&A_4.nonce()).unwrap(), &A_4.tx_hash().unwrap());
                assert_eq!(B_mappings.get(&B_1.nonce()).unwrap(), &B_1.tx_hash().unwrap());
                assert_eq!(B_mappings.get(&B_5.nonce()).unwrap(), &B_5.tx_hash().unwrap());
                assert_eq!(C_mappings.get(&C_5.nonce()).unwrap(), &C_5.tx_hash().unwrap());
                assert_eq!(C_mappings.get(&C_4.nonce()).unwrap(), &C_4.tx_hash().unwrap());
                assert_eq!(B_mappings.get(&B_4.nonce()).unwrap(), &B_4.tx_hash().unwrap());
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
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&C_1.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&B_4.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&B_5.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&C_3.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&C_4.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&C_5.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&A_4.tx_hash().unwrap()));
            assert!(mempool.orphan_set.contains(&A_5.tx_hash().unwrap()));

            // Append and validate stage 3
            for tx in stage_3.iter() {
                mempool.append_tx(tx.clone()).unwrap();
            }

            // Check tx lookup
            assert!(mempool.tx_lookup.contains_key(&A_3.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&B_2.tx_hash().unwrap()));
            assert!(mempool.tx_lookup.contains_key(&C_3.tx_hash().unwrap()));

            // Check timestamp lookup
            assert!(mempool.timestamp_lookup.contains_key(&A_3.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&B_2.tx_hash().unwrap()));
            assert!(mempool.timestamp_lookup.contains_key(&C_3.tx_hash().unwrap()));
            
            // Check timestamp reverse lookup
            let A_3_ts = mempool.timestamp_lookup.get(&A_3.tx_hash().unwrap()).unwrap().clone();
            let B_2_ts = mempool.timestamp_lookup.get(&B_2.tx_hash().unwrap()).unwrap().clone();
            let C_3_ts = mempool.timestamp_lookup.get(&C_3.tx_hash().unwrap()).unwrap().clone();

            assert_eq!(mempool.timestamp_reverse_lookup.get(&A_3_ts).unwrap(), &A_3.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&B_2_ts).unwrap(), &B_2.tx_hash().unwrap());
            assert_eq!(mempool.timestamp_reverse_lookup.get(&C_3_ts).unwrap(), &C_3.tx_hash().unwrap());

            // Check order of timestamps
            let (_, is_valid) = stage_3
                .iter()
                .fold((None, true), |(last, is_valid), cur| {
                    if !is_valid {
                        return (None, false);
                    }

                    if last.is_none() {
                        let ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap()).unwrap().clone();
                        (Some(ts), true)
                    } else {
                        let last = last.unwrap();
                        let cur_ts = mempool.timestamp_lookup.get(&cur.tx_hash().unwrap()).unwrap().clone();

                        if last < cur_ts {
                            (Some(cur_ts), true)
                        } else {
                            (None, false)
                        }
                    }
                });

            assert!(is_valid);

            // Check address mappings
            {
                let A_mappings = mempool.address_mappings.get(&A_addr).unwrap();
                let B_mappings = mempool.address_mappings.get(&B_addr).unwrap();
                let C_mappings = mempool.address_mappings.get(&C_addr).unwrap();

                assert_eq!(A_mappings.get(&A_3.nonce()).unwrap(), &A_3.tx_hash().unwrap());
                assert_eq!(B_mappings.get(&B_2.nonce()).unwrap(), &B_2.tx_hash().unwrap());
                assert_eq!(C_mappings.get(&C_3.nonce()).unwrap(), &C_3.tx_hash().unwrap());
            }

            // Check fee map
            {
                let fee_map = mempool.fee_map.get(&cur_hash).unwrap();

                assert!(fee_map.get(&A_3.fee()).is_some());
                assert!(fee_map.get(&B_2.fee()).is_some());
                assert!(fee_map.get(&C_3.fee()).is_some());
            }

            // Check orphan pool
            assert!(!mempool.orphan_set.contains(&A_1.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&A_2.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&C_1.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&B_1.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&B_4.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&B_5.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&C_3.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&C_4.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&C_5.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&A_4.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&A_5.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&A_3.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&B_2.tx_hash().unwrap()));
            assert!(!mempool.orphan_set.contains(&C_3.tx_hash().unwrap()));

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