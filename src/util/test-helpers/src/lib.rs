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

extern crate account;
extern crate crypto;
extern crate hex;
extern crate patricia_trie;
extern crate persistence;
extern crate quicksort;
extern crate rlp;
extern crate tempdir;

use account::{NormalAddress, Balance};
use crypto::Hash;
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec, PersistentDb};
use quicksort::*;
use std::sync::Arc;
use tempdir::TempDir;

pub use quicksort::*;

pub fn init_tempdb() -> PersistentDb {
    PersistentDb::new_in_memory()
}

pub fn init_balance(
    trie: &mut TrieDBMut<BlakeDbHasher, Codec>,
    address: NormalAddress,
    asset_hash: Hash,
    amount: &[u8],
) {
    let bin_asset_hash = asset_hash.to_vec();

    let cur_key = [address.as_bytes(), &b"."[..], &bin_asset_hash].concat();
    let nonce_key = [address.as_bytes(), &b".n"[..]].concat();
    let precision_key = [&bin_asset_hash, &b".p"[..]].concat();
    let address_mapping_key = [address.as_bytes(), &b".am"[..]].concat();

    // Re-serialize balance to validate with regex
    let balance = Balance::from_bytes(amount).unwrap().to_bytes();

    if let Ok(None) = trie.get(&precision_key) {
        trie.insert(&precision_key, &[18]).unwrap();
    }

    trie.insert(&address_mapping_key, address.as_bytes()).unwrap();
    trie.insert(&cur_key, &balance).unwrap();
    trie.insert(&nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
}
