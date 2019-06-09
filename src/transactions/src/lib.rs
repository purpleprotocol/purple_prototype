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

#[cfg(test)]
extern crate tempfile;

#[cfg(test)]
extern crate kvdb_rocksdb;

#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate bin_tools;

extern crate account;
extern crate byteorder;
extern crate crypto;
extern crate elastic_array;
extern crate hashdb;
extern crate hex;
extern crate network;
extern crate patricia_trie;
extern crate persistence;
extern crate purple_vm;
extern crate rand;
extern crate rust_decimal;
extern crate serde;
extern crate bitvec;

#[macro_use]
mod macros;

mod burn;
mod call;
mod change_minter;
mod create_currency;
mod create_mintable;
mod create_unique;
mod genesis;
mod mint;
mod open_contract;
mod send;

pub use burn::*;
pub use call::*;
pub use create_currency::*;
pub use create_mintable::*;
pub use change_minter::*;
pub use create_unique::*;
pub use genesis::*;
pub use mint::*;
pub use open_contract::*;
pub use send::*;

use crypto::Identity;
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use quickcheck::Arbitrary;
use rand::Rng;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Tx {
    Call(Call),
    OpenContract(OpenContract),
    Send(Send),
    Burn(Burn),
    CreateCurrency(CreateCurrency),
    CreateMintable(CreateMintable),
    Mint(Mint),
}

impl Tx {
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        match *self {
            Tx::Call(ref tx) => tx.to_bytes(),
            Tx::OpenContract(ref tx) => tx.to_bytes(),
            Tx::Send(ref tx) => tx.to_bytes(),
            Tx::Burn(ref tx) => tx.to_bytes(),
            Tx::CreateCurrency(ref tx) => tx.to_bytes(),
            Tx::CreateMintable(ref tx) => tx.to_bytes(),
            Tx::Mint(ref tx) => tx.to_bytes(),
        }
    }

    pub fn compute_hash_message(&self) -> Vec<u8> {
        match *self {
            Tx::Call(ref tx) => tx.compute_hash_message(),
            Tx::OpenContract(ref tx) => tx.compute_hash_message(),
            Tx::Send(ref tx) => tx.compute_hash_message(),
            Tx::Burn(ref tx) => tx.compute_hash_message(),
            Tx::CreateCurrency(ref tx) => tx.compute_hash_message(),
            Tx::CreateMintable(ref tx) => tx.compute_hash_message(),
            Tx::Mint(ref tx) => tx.compute_hash_message(),
        }
    }

    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>) -> Tx {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 6);
        let id = Identity::new();

        match random {
            0 => Tx::OpenContract(OpenContract::arbitrary_valid(trie, id.skey().clone())),
            1 => Tx::Send(Send::arbitrary_valid(trie, id.skey().clone())),
            2 => Tx::Burn(Burn::arbitrary_valid(trie, id.skey().clone())),
            3 => Tx::CreateCurrency(CreateCurrency::arbitrary_valid(trie, id.skey().clone())),
            4 => Tx::CreateMintable(CreateMintable::arbitrary_valid(trie, id.skey().clone())),
            5 => Tx::Mint(Mint::arbitrary_valid(trie, id.skey().clone())),
            _ => panic!(),
        }
    }
}

impl Arbitrary for Tx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Tx {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 7);

        match random {
            0 => Tx::Call(Arbitrary::arbitrary(g)),
            1 => Tx::OpenContract(Arbitrary::arbitrary(g)),
            2 => Tx::Send(Arbitrary::arbitrary(g)),
            3 => Tx::Burn(Arbitrary::arbitrary(g)),
            4 => Tx::CreateCurrency(Arbitrary::arbitrary(g)),
            5 => Tx::CreateMintable(Arbitrary::arbitrary(g)),
            6 => Tx::Mint(Arbitrary::arbitrary(g)),
            _ => panic!(),
        }
    }
}
