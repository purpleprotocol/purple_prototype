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

use account::{Balance, NormalAddress};
use crypto::{Hash, ShortHash};
use patricia_trie::{Trie, TrieDB, TrieDBMut, TrieMut};
use persistence::{Codec, DbHasher};
use std::default::Default;

#[cfg(any(test, feature = "test"))]
use crate::TestAccount;

/// The name of the main currency
pub const MAIN_CUR_NAME: &'static [u8] = b"purple";

/// The main currency coin supply
pub(crate) const COIN_SUPPLY: u64 = 500000000;

/// Balances that will be initialized with the genesis transaction
pub(crate) const INIT_ACCOUNTS: &'static [(&'static str, u64)] = &[];

#[derive(Debug, Clone, PartialEq)]
pub struct Genesis {
    asset_hash: ShortHash,
    coin_supply: u64,
}

impl Default for Genesis {
    fn default() -> Genesis {
        let main_asset_hash = crypto::hash_slice(MAIN_CUR_NAME).to_short();

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
    pub fn apply(&self, trie: &mut TrieDBMut<DbHasher, Codec>) {
        let bin_asset_hash = &self.asset_hash.0;
        let coin_supply = Balance::from_u64(self.coin_supply).to_bytes();
        let mut coinbase_supply = COIN_SUPPLY;

        #[cfg(any(test, feature = "test"))]
        let iterable_vec: Vec<(NormalAddress, u64)> = vec![
            (TestAccount::A.to_perm_address(), 100000),
            (TestAccount::B.to_perm_address(), 100000),
            (TestAccount::C.to_perm_address(), 100000),
        ];

        #[cfg(any(test, feature = "test"))]
        let iterable = iterable_vec.iter();

        #[cfg(not(any(test, feature = "test")))]
        let iterable = INIT_ACCOUNTS
            .iter()
            .map(|(a, b)| (NormalAddress::from_base58(a).unwrap(), b));

        // Write initial balances
        for (addr, balance) in iterable {
            if *balance > coinbase_supply {
                panic!("We are assigning more coins than there are in the coinbase! This shouldn't ever happen...");
            }

            coinbase_supply -= balance;

            let nonce_key = [addr.as_bytes(), &b".n"[..]].concat();
            let addr_mapping_key = [addr.as_bytes(), &b".am"[..]].concat();
            let cur_key = [addr.as_bytes(), &b"."[..], bin_asset_hash].concat();
            let balance = Balance::from_u64(*balance).to_bytes();

            trie.insert(&nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            trie.insert(&cur_key, &balance).unwrap();
            trie.insert(&addr_mapping_key, addr.as_bytes()).unwrap();
        }

        // Insert coinbase supply
        let coinbase_cur_key = [&b"coinbase."[..], bin_asset_hash].concat();
        let balance = Balance::from_u64(coinbase_supply).to_bytes();

        trie.insert(&coinbase_cur_key, &balance).unwrap();
    }
}
