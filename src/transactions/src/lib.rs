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
use crypto::{ShortHash, Hash, SecretKey, PublicKey, FromBase58, Identity};
use patricia_trie::{TrieDBMut, TrieDB, TrieMut, Trie};
use persistence::{BlakeDbHasher, Codec};
use quickcheck::Arbitrary;
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
pub enum Tx {
    Call(Call, usize),
    OpenContract(OpenContract, usize),
    Send(Send, usize),
    Burn(Burn, usize),
    CreateCurrency(CreateCurrency, usize),
    CreateMintable(CreateMintable, usize),
    Mint(Mint, usize),
    CreateUnique(CreateUnique, usize),
    ChangeMinter(ChangeMinter, usize),
}

impl Tx {
    pub fn validate(&self, trie: &TrieDB<BlakeDbHasher, Codec>) -> bool {
        match *self {
            Tx::Call(ref tx, _) => tx.validate(trie),
            Tx::OpenContract(ref tx, _) => tx.validate(trie),
            Tx::Send(ref tx, _) => tx.validate(trie),
            Tx::Burn(ref tx, _) => tx.validate(trie),
            Tx::CreateCurrency(ref tx, _) => tx.validate(trie),
            Tx::CreateMintable(ref tx, _) => tx.validate(trie),
            Tx::Mint(ref tx, _) => tx.validate(trie),
            Tx::CreateUnique(ref tx, _) => tx.validate(trie),
            Tx::ChangeMinter(ref tx, _) => tx.validate(trie),
        }
    }

    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        match *self {
            Tx::Call(ref tx, _) => tx.apply(trie),
            Tx::OpenContract(ref tx, _) => tx.apply(trie),
            Tx::Send(ref tx, _) => tx.apply(trie),
            Tx::Burn(ref tx, _) => tx.apply(trie),
            Tx::CreateCurrency(ref tx, _) => tx.apply(trie),
            Tx::CreateMintable(ref tx, _) => tx.apply(trie),
            Tx::Mint(ref tx, _) => tx.apply(trie),
            Tx::CreateUnique(ref tx, _) => tx.apply(trie),
            Tx::ChangeMinter(ref tx, _) => tx.apply(trie),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        match *self {
            Tx::Call(ref tx, _) => tx.to_bytes(),
            Tx::OpenContract(ref tx, _) => tx.to_bytes(),
            Tx::Send(ref tx, _) => tx.to_bytes(),
            Tx::Burn(ref tx, _) => tx.to_bytes(),
            Tx::CreateCurrency(ref tx, _) => tx.to_bytes(),
            Tx::CreateMintable(ref tx, _) => tx.to_bytes(),
            Tx::Mint(ref tx, _) => tx.to_bytes(),
            Tx::CreateUnique(ref tx, _) => tx.to_bytes(),
            Tx::ChangeMinter(ref tx, _) => tx.to_bytes(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Tx, &'static str> {
        if bytes.len() <= 1 {
            return Err("Invalid transaction size!");
        }

        let tx_type = bytes[0];
        
        match tx_type {
            Call::TX_TYPE => Ok(Tx::Call(Call::from_bytes(bytes)?, bytes.len() - 1)),
            Send::TX_TYPE => Ok(Tx::Send(Send::from_bytes(bytes)?, bytes.len() - 1)),
            ChangeMinter::TX_TYPE => Ok(Tx::ChangeMinter(ChangeMinter::from_bytes(bytes)?, bytes.len() - 1)),
            Burn::TX_TYPE => Ok(Tx::Burn(Burn::from_bytes(bytes)?, bytes.len() - 1)),
            CreateCurrency::TX_TYPE => Ok(Tx::CreateCurrency(CreateCurrency::from_bytes(bytes)?, bytes.len() - 1)),
            CreateMintable::TX_TYPE => Ok(Tx::CreateMintable(CreateMintable::from_bytes(bytes)?, bytes.len() - 1)),
            CreateUnique::TX_TYPE => Ok(Tx::CreateUnique(CreateUnique::from_bytes(bytes)?, bytes.len() - 1)),
            Mint::TX_TYPE => Ok(Tx::Mint(Mint::from_bytes(bytes)?, bytes.len() - 1)),
            OpenContract::TX_TYPE => Ok(Tx::OpenContract(OpenContract::from_bytes(bytes)?, bytes.len() - 1)),
            _ => Err("Invalid transaction type!")
        }
    }

    pub fn compute_hash_message(&self) -> Vec<u8> {
        match *self {
            Tx::Call(ref tx, _) => tx.compute_hash_message(),
            Tx::OpenContract(ref tx, _) => tx.compute_hash_message(),
            Tx::Send(ref tx, _) => tx.compute_hash_message(),
            Tx::Burn(ref tx, _) => tx.compute_hash_message(),
            Tx::CreateCurrency(ref tx, _) => tx.compute_hash_message(),
            Tx::CreateMintable(ref tx, _) => tx.compute_hash_message(),
            Tx::Mint(ref tx, _) => tx.compute_hash_message(),
            Tx::CreateUnique(ref tx, _) => tx.compute_hash_message(),
            Tx::ChangeMinter(ref tx, _) => tx.compute_hash_message(),
        }
    }

    pub fn transaction_hash(&self) -> Option<Hash> {
        match *self {
            Tx::Call(ref tx, _) => tx.hash,
            Tx::OpenContract(ref tx, _) => tx.hash,
            Tx::Send(ref tx, _) => tx.hash,
            Tx::Burn(ref tx, _) => tx.hash,
            Tx::CreateCurrency(ref tx, _) => tx.hash,
            Tx::CreateMintable(ref tx, _) => tx.hash,
            Tx::Mint(ref tx, _) => tx.hash,
            Tx::CreateUnique(ref tx, _) => tx.hash,
            Tx::ChangeMinter(ref tx, _) => tx.hash,
        }
    }

    pub fn nonce(&self) -> u64 {
        match *self {
            Tx::Call(ref tx, _) => tx.nonce,
            Tx::OpenContract(ref tx, _) => tx.nonce,
            Tx::Send(ref tx, _) => tx.nonce,
            Tx::Burn(ref tx, _) => tx.nonce,
            Tx::CreateCurrency(ref tx, _) => tx.nonce,
            Tx::CreateMintable(ref tx, _) => tx.nonce,
            Tx::Mint(ref tx, _) => tx.nonce,
            Tx::CreateUnique(ref tx, _) => tx.nonce,
            Tx::ChangeMinter(ref tx, _) => tx.nonce,
        }
    }

    pub fn tx_hash(&self) -> Option<Hash> {
        match *self {
            Tx::Call(ref tx, _) => tx.hash,
            Tx::OpenContract(ref tx, _) => tx.hash,
            Tx::Send(ref tx, _) => tx.hash,
            Tx::Burn(ref tx, _) => tx.hash,
            Tx::CreateCurrency(ref tx, _) => tx.hash,
            Tx::CreateMintable(ref tx, _) => tx.hash,
            Tx::Mint(ref tx, _) => tx.hash,
            Tx::CreateUnique(ref tx, _) => tx.hash,
            Tx::ChangeMinter(ref tx, _) => tx.hash,
        }
    }

    pub fn fee(&self) -> Balance {
        match *self {
            Tx::Call(ref tx, _) => tx.fee.clone(),
            Tx::OpenContract(ref tx, _) => tx.fee.clone(),
            Tx::Send(ref tx, _) => tx.fee.clone(),
            Tx::Burn(ref tx, _) => tx.fee.clone(),
            Tx::CreateCurrency(ref tx, _) => tx.fee.clone(),
            Tx::CreateMintable(ref tx, _) => tx.fee.clone(),
            Tx::Mint(ref tx, _) => tx.fee.clone(),
            Tx::CreateUnique(ref tx, _) => tx.fee.clone(),
            Tx::ChangeMinter(ref tx, _) => tx.fee.clone(),
        }
    }

    pub fn fee_hash(&self) -> ShortHash {
        match *self {
            Tx::Call(ref tx, _) => tx.fee_hash,
            Tx::OpenContract(ref tx, _) => tx.fee_hash,
            Tx::Send(ref tx, _) => tx.fee_hash,
            Tx::Burn(ref tx, _) => tx.fee_hash,
            Tx::CreateCurrency(ref tx, _) => tx.fee_hash,
            Tx::CreateMintable(ref tx, _) => tx.fee_hash,
            Tx::Mint(ref tx, _) => tx.fee_hash,
            Tx::CreateUnique(ref tx, _) => tx.fee_hash,
            Tx::ChangeMinter(ref tx, _) => tx.fee_hash,
        }
    }

    /// Returns the signing address of the transaction creator.
    pub fn creator_signing_address(&self) -> NormalAddress {
        match *self {
            Tx::Call(ref tx, _) => NormalAddress::from_pkey(&tx.from),
            Tx::OpenContract(ref tx, _) => NormalAddress::from_pkey(&tx.creator),
            Tx::Send(ref tx, _) => NormalAddress::from_pkey(&tx.from),
            Tx::Burn(ref tx, _) => NormalAddress::from_pkey(&tx.burner),
            Tx::CreateCurrency(ref tx, _) => NormalAddress::from_pkey(&tx.creator),
            Tx::CreateMintable(ref tx, _) => NormalAddress::from_pkey(&tx.creator),
            Tx::Mint(ref tx, _) => NormalAddress::from_pkey(&tx.minter),
            Tx::CreateUnique(ref tx, _) => NormalAddress::from_pkey(&tx.creator),
            Tx::ChangeMinter(ref tx, _) => NormalAddress::from_pkey(&tx.minter),
        }
    }

    pub fn next_address(&self) -> NormalAddress {
        match *self {
            Tx::Call(ref tx, _) => tx.next_address.clone(),
            Tx::OpenContract(ref tx, _) => tx.next_address.clone(),
            Tx::Send(ref tx, _) => tx.next_address.clone(),
            Tx::Burn(ref tx, _) => tx.next_address.clone(),
            Tx::CreateCurrency(ref tx, _) => tx.next_address.clone(),
            Tx::CreateMintable(ref tx, _) => tx.next_address.clone(),
            Tx::Mint(ref tx, _) => tx.next_address.clone(),
            Tx::CreateUnique(ref tx, _) => tx.next_address.clone(),
            Tx::ChangeMinter(ref tx, _) => tx.next_address.clone(),
        }
    }

    /// Returns the size in bytes of a transaction.
    pub fn byte_size(&self) -> usize {
        match *self {
            Tx::Call(_, byte_size) => byte_size,
            Tx::OpenContract(_, byte_size) => byte_size,
            Tx::Send(_, byte_size) => byte_size,
            Tx::Burn(_, byte_size) => byte_size,
            Tx::CreateCurrency(_, byte_size) => byte_size,
            Tx::CreateMintable(_, byte_size) => byte_size,
            Tx::Mint(_, byte_size) => byte_size,
            Tx::CreateUnique(_, byte_size) => byte_size,
            Tx::ChangeMinter(_, byte_size) => byte_size,
        }
    }

    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>) -> Tx {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 8);
        let id = Identity::new();

        match random {
            0 => {
                let tx: Call = Call::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Call(tx, byte_size)
            },
            1 => {
                let tx: OpenContract = OpenContract::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::OpenContract(tx, byte_size)
            },
            2 => {
                let tx: Send = Send::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Send(tx, byte_size)
            },
            3 => {
                let tx: Burn = Burn::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Burn(tx, byte_size)
            },
            4 => {
                let tx: CreateCurrency = CreateCurrency::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::CreateCurrency(tx, byte_size)
            },
            5 => {
                let tx: CreateMintable = CreateMintable::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::CreateMintable(tx, byte_size)
            },
            6 => {
                let tx: Mint = Mint::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Mint(tx, byte_size)
            },
            7 => {
                let tx: CreateUnique = CreateUnique::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::CreateUnique(tx, byte_size)
            },
            8 => {
                let tx: ChangeMinter = ChangeMinter::arbitrary_valid(trie, id.skey().clone());
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::ChangeMinter(tx, byte_size)
            },
            _ => panic!(),
        }
    }
}

impl Arbitrary for Tx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Tx {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 9);

        match random {
            0 => {
                let tx: Call = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Call(tx, byte_size)
            },
            1 => {
                let tx: OpenContract = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::OpenContract(tx, byte_size)
            },
            2 => {
                let tx: Send = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Send(tx, byte_size)
            },
            3 => {
                let tx: Burn = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Burn(tx, byte_size)
            },
            4 => {
                let tx: CreateCurrency = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::CreateCurrency(tx, byte_size)
            },
            5 => {
                let tx: CreateMintable = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::CreateMintable(tx, byte_size)
            },
            6 => {
                let tx: Mint = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::Mint(tx, byte_size)
            },
            7 => {
                let tx: CreateUnique = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::CreateUnique(tx, byte_size)
            },
            8 => {
                let tx: ChangeMinter = Arbitrary::arbitrary(g);
                let byte_size = tx.to_bytes().unwrap().len() - 1;
                Tx::ChangeMinter(tx, byte_size)
            },
            _ => panic!(),
        }
    }
}

#[cfg(any(test, feature = "test"))]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(any(test, feature = "test"))]
#[repr(u8)]
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum TestAccount {
    A = 0,
    B = 1,
    C = 2,
}

#[cfg(any(test, feature = "test"))]
impl TestAccount {
    pub fn to_perm_address(&self) -> NormalAddress {
        let id: u8 = match *self {
            TestAccount::A => 1,
            TestAccount::B => 2,
            TestAccount::C => 3,
        };
        let (pk, _) = crypto::gen_keypair_from_seed(&[&[id][..], &encode_be_u64!(1)].concat());
        NormalAddress::from_pkey(&pk)
    }

    pub fn to_signing_addr(&self, nonce: u64) -> NormalAddress {
        let id: u8 = match *self {
            TestAccount::A => 1,
            TestAccount::B => 2,
            TestAccount::C => 3,
        };
        let (pk, _) = crypto::gen_keypair_from_seed(&[&[id][..], &encode_be_u64!(nonce)].concat());
        NormalAddress::from_pkey(&pk)
    }

    pub fn to_pkey(&self, nonce: u64) -> PublicKey {
        let id: u8 = match *self {
            TestAccount::A => 1,
            TestAccount::B => 2,
            TestAccount::C => 3,
        };
        let (pk, _) = crypto::gen_keypair_from_seed(&[&[id][..], &encode_be_u64!(nonce)].concat());
        pk
    }

    pub fn to_skey(&self, nonce: u64) -> SecretKey {
        let id: u8 = match *self {
            TestAccount::A => 1,
            TestAccount::B => 2,
            TestAccount::C => 3,
        };
        let (_, sk) = crypto::gen_keypair_from_seed(&[&[id][..], &encode_be_u64!(nonce)].concat());
        sk
    }
}

#[cfg(any(test, feature = "test"))]
/// Helper to create test `Send` transactions between the
/// genesis test accounts. 
pub fn send_coins(sender: TestAccount, receiver: TestAccount, amount: u64, fee: u64, sender_nonce: u64) -> Tx {
    assert_ne!(sender, receiver);

    let sender_pkey = sender.to_pkey(sender_nonce);
    
    let mut tx = Send {
        from: sender_pkey,
        next_address: sender.to_signing_addr(sender_nonce + 1),
        to: Address::Normal(receiver.to_perm_address()),
        amount: Balance::from_u64(amount),
        fee: Balance::from_u64(fee),
        asset_hash: crypto::hash_slice(crate::genesis::MAIN_CUR_NAME).to_short(),
        fee_hash: crypto::hash_slice(crate::genesis::MAIN_CUR_NAME).to_short(),
        nonce: sender_nonce,
        signature: None,
        hash: None,
    };

    tx.sign(sender.to_skey(sender_nonce));
    tx.compute_hash();
    let byte_size = tx.to_bytes().unwrap().len() - 1;
    Tx::Send(tx, byte_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Tx) -> bool {
            tx == Tx::from_bytes(&Tx::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}