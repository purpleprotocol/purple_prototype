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

use crate::{Send, Tx};
use account::{Address, Balance, NormalAddress};
use constants::*;
use crypto::{PublicKey, SecretKey};
use lazy_static::*;
use triomphe::Arc;

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
lazy_static! {
    static ref A_NONCE: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
    static ref B_NONCE: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
    static ref C_NONCE: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
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
pub fn send_coins(
    sender: TestAccount,
    receiver: TestAccount,
    amount: u64,
    fee: u64,
    sender_nonce: u64,
) -> Tx {
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

#[cfg(any(test, feature = "test"))]
pub fn get_tx_list_of_size(size: usize) -> Result<Vec<Arc<Tx>>, &'static str> {
    if (size == 0 || size > MAX_TX_SET_SIZE) {
        return Err("Invalid size");
    }

    let mut tx_list = Vec::<Arc<Tx>>::new();
    let mut current_size = 0;

    while current_size <= MAX_TX_SET_SIZE {
        let nonce = A_NONCE.fetch_add(1, Ordering::SeqCst);
        let mut send_tx = send_coins(TestAccount::A, TestAccount::B, 1, 10, nonce);
        let new_size = send_tx.byte_size() + current_size;
        if (new_size > MAX_TX_SET_SIZE) {
            break;
        }

        tx_list.push(Arc::new(send_tx));
        current_size = new_size;
    }

    Ok(tx_list)
}
