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

const TREASURY_SHAREHOLDER: &'static str = "Zmr68nPzntEBr3Tq2NNiaNUdgjpECDqrKscwwef2aBMk"; // TODO: Change this
const MAIN_CUR_NAME: &'static [u8] = b"purple";
const COIN_SUPPLY: u64 = 500000000;
const TREASURY_ADDRESS_PRIMITIVE: &'static [u8] = b"treasury";
const TREASURY_STOCK_PRIMITIVE: &'static [u8] = b"treasury_stock";
const TREASURY_INITIAL_BALANCE: &'static [u8] = b"125000000.0"; // 25% of the coin supply
const TREASURY_ISSUED_SHARES: u32 = 1000000;
const TREASURY_AUTHORIZED_SHARES: u32 = 1000000;

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
        let main_cur_hash = crypto::hash_slice(MAIN_CUR_NAME);
        let treasury_address = crypto::hash_slice(TREASURY_ADDRESS_PRIMITIVE);
        let treasury_stock_hash = crypto::hash_slice(TREASURY_STOCK_PRIMITIVE);
        let shareholder_address = NormalAddress::from_base58(TREASURY_SHAREHOLDER).unwrap();
        let mut treasury_share_map = ShareMap::new();

        treasury_share_map.add_shareholder(shareholder_address, TREASURY_ISSUED_SHARES);

        Genesis {
            coin_supply: COIN_SUPPLY,
            treasury_balance: Balance::from_bytes(TREASURY_INITIAL_BALANCE).unwrap(), 
            treasury_address: ShareholdersAddress::new(treasury_address.0),
            treasury_shares: Shares::new(TREASURY_ISSUED_SHARES, TREASURY_AUTHORIZED_SHARES, 80),
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
        match trie.get(b"treasury") {
            Ok(Some(_)) => {
                panic!("The treasury account already exists!");
            },
            Ok(None) => {
                let bin_addr = &self.treasury_address.to_bytes();
                let bin_shares = &self.treasury_shares.to_bytes();
                let bin_share_map = &self.treasury_share_map.to_bytes();
                let bin_stock_hash = &self.treasury_stock_hash.to_vec();
                let bin_cur_hash = &self.currency_hash.to_vec();
                let hex_addr = hex::encode(bin_addr);
                let hex_cur_hash = hex::encode(bin_cur_hash);
                let nonce_key = format!("{}.n", hex_addr);
                let nonce_key = nonce_key.as_bytes();
                let shares_key = format!("{}.s", hex_addr);
                let shares_key = shares_key.as_bytes();
                let share_map_key = format!("{}.sm", hex_addr);
                let share_map_key = share_map_key.as_bytes();
                let stock_hash_key = format!("{}.sh", hex_addr);
                let stock_hash_key = stock_hash_key.as_bytes();
                let treasury_cur_key = format!("{}.{}", hex_addr, hex_cur_hash);
                let treasury_cur_key = treasury_cur_key.as_bytes();
                let coin_supply = format!("{}.0", &self.coin_supply);
                let coin_supply = coin_supply.as_bytes();
                let currencies = rlp::encode_list::<Vec<u8>, _>(&vec![bin_cur_hash]);

                // Insert treasury data
                trie.insert(b"treasury", &bin_addr).unwrap();
                trie.insert(nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
                trie.insert(shares_key, &bin_shares).unwrap();
                trie.insert(share_map_key, &bin_share_map).unwrap();
                trie.insert(stock_hash_key, &bin_stock_hash).unwrap();
                trie.insert(treasury_cur_key, &coin_supply).unwrap();

                // Init currencies index and list main currency
                trie.insert(b"ci", &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
                trie.insert(b"c.0", &currencies).unwrap();
            },
            Err(err) => panic!(err)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test_helpers;

    use super::*;

    #[test]
    fn apply_it_initializes_the_treasury() {
        let main_cur_hash = crypto::hash_slice(MAIN_CUR_NAME);
        let treasury_address = crypto::hash_slice(TREASURY_ADDRESS_PRIMITIVE);
        let treasury_address = ShareholdersAddress::new(treasury_address.0);
        let treasury_stock_hash = crypto::hash_slice(TREASURY_STOCK_PRIMITIVE);
        let shareholder_address = NormalAddress::from_base58(TREASURY_SHAREHOLDER).unwrap();
        let treasury_shares = Shares::new(TREASURY_ISSUED_SHARES, TREASURY_AUTHORIZED_SHARES, 80);
        let mut treasury_share_map = ShareMap::new();

        treasury_share_map.add_shareholder(shareholder_address, TREASURY_ISSUED_SHARES);

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
        let tx: Genesis = Default::default();

        let bin_addr = treasury_address.to_bytes();
        let bin_shares = treasury_shares.to_bytes();
        let bin_share_map = treasury_share_map.to_bytes();
        let bin_stock_hash = treasury_stock_hash.to_vec();
        let bin_cur_hash = main_cur_hash.to_vec();
        let hex_addr = hex::encode(bin_addr);
        let hex_cur_hash = hex::encode(bin_cur_hash.clone());
        let nonce_key = format!("{}.n", hex_addr);
        let nonce_key = nonce_key.as_bytes();
        let shares_key = format!("{}.s", hex_addr);
        let shares_key = shares_key.as_bytes();
        let share_map_key = format!("{}.sm", hex_addr);
        let share_map_key = share_map_key.as_bytes();
        let stock_hash_key = format!("{}.sh", hex_addr);
        let stock_hash_key = stock_hash_key.as_bytes();
        let treasury_cur_key = format!("{}.{}", hex_addr, hex_cur_hash);
        let treasury_cur_key = treasury_cur_key.as_bytes();
        let coin_supply = format!("{}.0", COIN_SUPPLY);
        let coin_supply = coin_supply.as_bytes();
        let currencies = rlp::encode_list::<Vec<u8>, _>(&vec![bin_cur_hash]);

        // Apply genesis to state
        tx.apply(&mut trie);

        assert_eq!(&trie.get(b"treasury").unwrap().unwrap(), &treasury_address.to_bytes());
        assert_eq!(&trie.get(nonce_key).unwrap().unwrap(), &vec![0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&trie.get(shares_key).unwrap().unwrap(), &bin_shares);
        assert_eq!(&trie.get(share_map_key).unwrap().unwrap(), &bin_share_map);
        assert_eq!(&trie.get(stock_hash_key).unwrap().unwrap(), &bin_stock_hash);
        assert_eq!(&trie.get(treasury_cur_key).unwrap().unwrap(), &coin_supply);

        // Init currencies index and list main currency
        assert_eq!(&trie.get(b"ci").unwrap().unwrap(), &vec![0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&trie.get(b"c.0").unwrap().unwrap(), &currencies);
    }
}