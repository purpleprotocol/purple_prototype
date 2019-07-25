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

use account::{Balance, NormalAddress};
use crypto::Hash;
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use std::default::Default;

/// The name of the main currency
const MAIN_CUR_NAME: &'static [u8] = b"purple";

/// The main currency coin supply
const COIN_SUPPLY: u64 = 500000000;

/// Balances that will be initialized with the genesis transaction
const INIT_BALANCES: &'static [(NormalAddress, u64)] = &[];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Genesis {
    asset_hash: Hash,
    coin_supply: u64,
}

impl Default for Genesis {
    fn default() -> Genesis {
        let main_asset_hash = crypto::hash_slice(MAIN_CUR_NAME);

        Genesis {
            coin_supply: COIN_SUPPLY,
            asset_hash: main_asset_hash,
        }
    }
}

impl Genesis {
    /// Applies the genesis transaction to the provided database.
    ///
    /// This function will panic if the treasury account already exists.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        match trie.get(b"treasury") {
            Ok(Some(_)) => {
                panic!("The treasury account already exists!");
            }
            Ok(None) => {
                let bin_asset_hash = &self.asset_hash.to_vec();
                let asset_hash = hex::encode(&bin_asset_hash);
                let coin_supply = format!("{}.0", &self.coin_supply);
                let coin_supply = coin_supply.as_bytes();
                let currencies = rlp::encode_list::<Vec<u8>, _>(&vec![bin_asset_hash]);
                let mut coinbase_supply = COIN_SUPPLY;

                // Write initial balances
                for (addr, balance) in INIT_BALANCES.iter() {
                    if *balance > coinbase_supply {
                        panic!("We are assigning more coins than there are in the coinbase! This shouldn't ever happen...");
                    }

                    coinbase_supply -= balance;

                    let bin_addr = addr.to_bytes();
                    let addr = hex::encode(&bin_addr);
                    let nonce_key = format!("{}.n", addr);
                    let nonce_key = nonce_key.as_bytes();
                    let cur_key = format!("{}.{}", addr, asset_hash);
                    let cur_key = cur_key.as_bytes();
                    let balance = format!("{}.0", balance);
                    let balance = balance.as_bytes();

                    trie.insert(nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
                    trie.insert(cur_key, &balance).unwrap();
                }

                // Insert coinbase supply
                let coinbase_cur_key = format!("coinbase.{}", asset_hash);
                let coinbase_cur_key = coinbase_cur_key.as_bytes();
                let balance = format!("{}.0", coinbase_supply);
                let balance = balance.as_bytes();

                trie.insert(coinbase_cur_key, &balance).unwrap();

                // Init currencies index and list main currency
                trie.insert(b"ci", &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
                trie.insert(b"c.0", &currencies).unwrap();
            }
            Err(err) => panic!(err),
        }
    }
}
