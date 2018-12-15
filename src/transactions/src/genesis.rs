/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

use account::{ShareholdersAddress, NormalAddress, ShareMap, Balance, Shares};
use crypto::{Hash, Signature};
use patricia_trie::{TrieMut, TrieDBMut};
use persistence::{BlakeDbHasher, Codec};
use std::default::Default;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Genesis {
    treasury_balance: Balance,
    treasury_address: ShareholdersAddress,
    treasury_shares: Shares,
    treasury_share_map: ShareMap,
    treasury_stock_hash: Hash,
    currency_hash: Hash,
    coin_supply: u64,
}

impl Default for Genesis {
    fn default() -> Genesis {
        let main_cur_hash = crypto::hash_slice(b"purple");
        let treasury_address = crypto::hash_slice(b"treasury");
        let treasury_stock_hash = crypto::hash_slice(b"treasury_stock");
        let shareholder_address = NormalAddress::from_base58("Zmr68nPzntEBr3Tq2NNiaNUdgjpECDqrKscwwef2aBMk").unwrap(); // TODO: Change this
        let mut treasury_share_map = ShareMap::new();

        treasury_share_map.add_shareholder(shareholder_address, 1000000);

        Genesis {
            coin_supply: 500000000,
            treasury_balance: Balance::from_bytes(b"125000000.0").unwrap(), // 25% of the coin supply
            treasury_address: ShareholdersAddress::new(treasury_address.0),
            treasury_shares: Shares::new(1000000, 10000000, 80),
            treasury_share_map: treasury_share_map,
            treasury_stock_hash: treasury_stock_hash,
            currency_hash: main_cur_hash
        }
    }
}

impl Genesis {
    /// Applies the genesis transaction to the provided database.
    ///
    /// This function will panic if the treasury account already exists.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    extern crate test_helpers;

    use super::*;

    #[test]
    fn apply_it_initializes_the_treasury() {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
        let tx: Genesis = Default::default();

        // Apply genesis to state
        tx.apply(&mut trie);

        assert!(false);
    }
}