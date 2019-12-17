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

#[cfg(test)]
extern crate tempfile;

#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate bin_tools;

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

pub use crate::burn::*;
pub use crate::call::*;
pub use crate::change_minter::*;
pub use crate::create_currency::*;
pub use crate::create_mintable::*;
pub use crate::create_unique::*;
pub use crate::genesis::*;
pub use crate::mint::*;
pub use crate::open_contract::*;
pub use crate::send::*;

use account::{Address, NormalAddress, Balance};
use crypto::{Hash, SecretKey, FromBase58, Identity};
use patricia_trie::{TrieDBMut, TrieDB, TrieMut, Trie};
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
    CreateUnique(CreateUnique),
    ChangeMinter(ChangeMinter),
}

impl Tx {
    pub fn validate(&self, trie: &TrieDB<BlakeDbHasher, Codec>) -> bool {
        match *self {
            Tx::Call(ref tx) => tx.validate(trie),
            Tx::OpenContract(ref tx) => tx.validate(trie),
            Tx::Send(ref tx) => tx.validate(trie),
            Tx::Burn(ref tx) => tx.validate(trie),
            Tx::CreateCurrency(ref tx) => tx.validate(trie),
            Tx::CreateMintable(ref tx) => tx.validate(trie),
            Tx::Mint(ref tx) => tx.validate(trie),
            Tx::CreateUnique(ref tx) => tx.validate(trie),
            Tx::ChangeMinter(ref tx) => tx.validate(trie),
        }
    }

    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        match *self {
            Tx::Call(ref tx) => tx.apply(trie),
            Tx::OpenContract(ref tx) => tx.apply(trie),
            Tx::Send(ref tx) => tx.apply(trie),
            Tx::Burn(ref tx) => tx.apply(trie),
            Tx::CreateCurrency(ref tx) => tx.apply(trie),
            Tx::CreateMintable(ref tx) => tx.apply(trie),
            Tx::Mint(ref tx) => tx.apply(trie),
            Tx::CreateUnique(ref tx) => tx.apply(trie),
            Tx::ChangeMinter(ref tx) => tx.apply(trie),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        match *self {
            Tx::Call(ref tx) => tx.to_bytes(),
            Tx::OpenContract(ref tx) => tx.to_bytes(),
            Tx::Send(ref tx) => tx.to_bytes(),
            Tx::Burn(ref tx) => tx.to_bytes(),
            Tx::CreateCurrency(ref tx) => tx.to_bytes(),
            Tx::CreateMintable(ref tx) => tx.to_bytes(),
            Tx::Mint(ref tx) => tx.to_bytes(),
            Tx::CreateUnique(ref tx) => tx.to_bytes(),
            Tx::ChangeMinter(ref tx) => tx.to_bytes(),
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
            Tx::CreateUnique(ref tx) => tx.compute_hash_message(),
            Tx::ChangeMinter(ref tx) => tx.compute_hash_message(),
        }
    }

    pub fn transaction_hash(&self) -> Option<Hash> {
        match *self {
            Tx::Call(ref tx) => tx.hash,
            Tx::OpenContract(ref tx) => tx.hash,
            Tx::Send(ref tx) => tx.hash,
            Tx::Burn(ref tx) => tx.hash,
            Tx::CreateCurrency(ref tx) => tx.hash,
            Tx::CreateMintable(ref tx) => tx.hash,
            Tx::Mint(ref tx) => tx.hash,
            Tx::CreateUnique(ref tx) => tx.hash,
            Tx::ChangeMinter(ref tx) => tx.hash,
        }
    }

    pub fn nonce(&self) -> u64 {
        match *self {
            Tx::Call(ref tx) => tx.nonce,
            Tx::OpenContract(ref tx) => tx.nonce,
            Tx::Send(ref tx) => tx.nonce,
            Tx::Burn(ref tx) => tx.nonce,
            Tx::CreateCurrency(ref tx) => tx.nonce,
            Tx::CreateMintable(ref tx) => tx.nonce,
            Tx::Mint(ref tx) => tx.nonce,
            Tx::CreateUnique(ref tx) => tx.nonce,
            Tx::ChangeMinter(ref tx) => tx.nonce,
        }
    }

    pub fn tx_hash(&self) -> Option<Hash> {
        match *self {
            Tx::Call(ref tx) => tx.hash,
            Tx::OpenContract(ref tx) => tx.hash,
            Tx::Send(ref tx) => tx.hash,
            Tx::Burn(ref tx) => tx.hash,
            Tx::CreateCurrency(ref tx) => tx.hash,
            Tx::CreateMintable(ref tx) => tx.hash,
            Tx::Mint(ref tx) => tx.hash,
            Tx::CreateUnique(ref tx) => tx.hash,
            Tx::ChangeMinter(ref tx) => tx.hash,
        }
    }

    pub fn fee(&self) -> Balance {
        match *self {
            Tx::Call(ref tx) => tx.fee.clone(),
            Tx::OpenContract(ref tx) => tx.fee.clone(),
            Tx::Send(ref tx) => tx.fee.clone(),
            Tx::Burn(ref tx) => tx.fee.clone(),
            Tx::CreateCurrency(ref tx) => tx.fee.clone(),
            Tx::CreateMintable(ref tx) => tx.fee.clone(),
            Tx::Mint(ref tx) => tx.fee.clone(),
            Tx::CreateUnique(ref tx) => tx.fee.clone(),
            Tx::ChangeMinter(ref tx) => tx.fee.clone(),
        }
    }

    pub fn fee_hash(&self) -> Hash {
        match *self {
            Tx::Call(ref tx) => tx.fee_hash,
            Tx::OpenContract(ref tx) => tx.fee_hash,
            Tx::Send(ref tx) => tx.fee_hash,
            Tx::Burn(ref tx) => tx.fee_hash,
            Tx::CreateCurrency(ref tx) => tx.fee_hash,
            Tx::CreateMintable(ref tx) => tx.fee_hash,
            Tx::Mint(ref tx) => tx.fee_hash,
            Tx::CreateUnique(ref tx) => tx.fee_hash,
            Tx::ChangeMinter(ref tx) => tx.fee_hash,
        }
    }

    /// Returns the signing address of the transaction creator.
    pub fn creator_signing_address(&self) -> Address {
        match *self {
            Tx::Call(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.from)),
            Tx::OpenContract(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.creator)),
            Tx::Send(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.from)),
            Tx::Burn(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.burner)),
            Tx::CreateCurrency(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.creator)),
            Tx::CreateMintable(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.creator)),
            Tx::Mint(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.minter)),
            Tx::CreateUnique(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.creator)),
            Tx::ChangeMinter(ref tx) => Address::Normal(NormalAddress::from_pkey(&tx.minter)),
        }
    }

    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>) -> Tx {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 8);
        let id = Identity::new();

        match random {
            0 => Tx::OpenContract(OpenContract::arbitrary_valid(trie, id.skey().clone())),
            1 => Tx::Send(Send::arbitrary_valid(trie, id.skey().clone())),
            2 => Tx::Burn(Burn::arbitrary_valid(trie, id.skey().clone())),
            3 => Tx::CreateCurrency(CreateCurrency::arbitrary_valid(trie, id.skey().clone())),
            4 => Tx::CreateMintable(CreateMintable::arbitrary_valid(trie, id.skey().clone())),
            5 => Tx::Mint(Mint::arbitrary_valid(trie, id.skey().clone())),
            6 => Tx::CreateUnique(CreateUnique::arbitrary_valid(trie, id.skey().clone())),
            7 => Tx::ChangeMinter(ChangeMinter::arbitrary_valid(trie, id.skey().clone())),
            _ => panic!(),
        }
    }
}

impl Arbitrary for Tx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Tx {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 9);

        match random {
            0 => Tx::Call(Arbitrary::arbitrary(g)),
            1 => Tx::OpenContract(Arbitrary::arbitrary(g)),
            2 => Tx::Send(Arbitrary::arbitrary(g)),
            3 => Tx::Burn(Arbitrary::arbitrary(g)),
            4 => Tx::CreateCurrency(Arbitrary::arbitrary(g)),
            5 => Tx::CreateMintable(Arbitrary::arbitrary(g)),
            6 => Tx::Mint(Arbitrary::arbitrary(g)),
            7 => Tx::CreateUnique(Arbitrary::arbitrary(g)),
            8 => Tx::ChangeMinter(Arbitrary::arbitrary(g)),
            _ => panic!(),
        }
    }
}

#[cfg(any(test, feature = "test"))]
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum TestAccount {
    A = 0,
    B = 1,
    C = 2,
}

#[cfg(any(test, feature = "test"))]
impl TestAccount {
    pub fn to_address(&self) -> Address {
        Address::from_base58(crate::genesis::INIT_ACCOUNTS[*self as usize].0).unwrap()
    }

    pub fn to_skey(&self) -> SecretKey {
        let key = crate::genesis::INIT_ACCOUNTS_SKEYS[*self as usize].from_base58().unwrap();
        let mut key_arr = [0; 64];
        key_arr.copy_from_slice(&key);
        SecretKey(key_arr)
    }
}

#[cfg(any(test, feature = "test"))]
/// Helper to create test `Send` transactions between the
/// genesis test accounts. 
pub fn send_coins(sender: TestAccount, receiver: TestAccount, amount: u64, fee: u64, nonce: u64) -> Tx {
    assert_ne!(sender, receiver);
    
    let mut tx = Send {
        from: sender.to_address().unwrap_normal(),
        to: receiver.to_address(),
        amount: Balance::from_u64(amount),
        fee: Balance::from_u64(fee),
        asset_hash: crypto::hash_slice(crate::genesis::MAIN_CUR_NAME),
        fee_hash: crypto::hash_slice(crate::genesis::MAIN_CUR_NAME),
        nonce,
        signature: None,
        hash: None,
    };

    tx.sign(sender.to_skey());
    tx.compute_hash();
    Tx::Send(tx)
}