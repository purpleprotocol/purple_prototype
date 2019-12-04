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

use account::{Address, Balance, NormalAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, PublicKey as Pk, SecretKey as Sk, Signature};
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use std::io::Cursor;
use std::str;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Send {
    pub(crate) from: NormalAddress,
    pub(crate) to: Address,
    pub(crate) amount: Balance,
    pub(crate) fee: Balance,
    pub(crate) asset_hash: Hash,
    pub(crate) fee_hash: Hash,
    pub(crate) nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature: Option<Signature>,
}

impl Send {
    pub const TX_TYPE: u8 = 3;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDBMut<BlakeDbHasher, Codec>) -> bool {
        let zero = Balance::from_bytes(b"0.0").unwrap();

        // You cannot send 0 coins
        if self.amount == zero {
            return false;
        }

        if !self.verify_sig() {
            return false;
        }

        let bin_sender = &self.from.to_bytes();
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;

        // Convert address to strings
        let sender = hex::encode(bin_sender);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let nonce_key = format!("{}.n", sender);
        let nonce_key = nonce_key.as_bytes();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let cur_key = format!("{}.{}", sender, asset_hash);
        let fee_key = format!("{}.{}", sender, fee_hash);

        // Retrieve serialized nonce
        let bin_nonce = match trie.get(&nonce_key) {
            Ok(Some(nonce)) => nonce,
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        let mut stored_nonce = decode_be_u64!(bin_nonce).unwrap();
        if stored_nonce + 1 != self.nonce {
            return false;
        }

        if fee_hash == asset_hash {
            // The transaction's fee is paid in the same currency
            // that is being sent, so we only retrieve one balance.
            let mut balance = match trie.get(&cur_key.as_bytes()) {
                Ok(Some(balance)) => match Balance::from_bytes(&balance) {
                    Ok(balance) => balance,
                    Err(err) => panic!(err),
                },
                Ok(None) => return false,
                Err(err) => panic!(err),
            };

            // Subtract fee from balance
            balance -= self.fee.clone();

            // Subtract amount transferred from balance
            balance -= self.amount.clone();

            balance >= zero
        } else {
            // The transaction's fee is paid in a different currency
            // than the one being transferred so we retrieve both balances.
            let mut cur_balance = match trie.get(&cur_key.as_bytes()) {
                Ok(Some(balance)) => match Balance::from_bytes(&balance) {
                    Ok(balance) => balance,
                    Err(err) => panic!(err),
                },
                Ok(None) => return false,
                Err(err) => panic!(err),
            };

            let mut fee_balance = match trie.get(&fee_key.as_bytes()) {
                Ok(Some(balance)) => match Balance::from_bytes(&balance) {
                    Ok(balance) => balance,
                    Err(err) => panic!(err),
                },
                Ok(None) => return false,
                Err(err) => panic!(err),
            };

            // Subtract fee from sender
            fee_balance -= self.fee.clone();

            // Subtract amount transferred from sender
            cur_balance -= self.amount.clone();

            cur_balance >= zero && fee_balance >= zero
        }
    }

    /// Applies the send transaction to the provided database.
    ///
    /// This function will panic if the `from` account does not exist.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_from = &self.from.to_bytes();
        let bin_to = &self.to.to_bytes();
        let bin_asset_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();

        // Convert addresses to strings
        let from = hex::encode(bin_from);
        let to = hex::encode(bin_to);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let from_nonce_key = format!("{}.n", from);
        let to_nonce_key = format!("{}.n", to);
        let from_nonce_key = from_nonce_key.as_bytes();
        let to_nonce_key = to_nonce_key.as_bytes();

        // Retrieve serialized nonces
        let bin_from_nonce = &trie.get(&from_nonce_key).unwrap().unwrap();
        let bin_to_nonce = trie.get(&to_nonce_key);

        // Read the nonce of the sender
        let mut from_nonce = decode_be_u64!(bin_from_nonce).unwrap();

        // Increment sender nonce
        from_nonce += 1;

        let from_nonce: Vec<u8> = encode_be_u64!(from_nonce);

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let from_cur_key = format!("{}.{}", from, asset_hash);
        let from_fee_key = format!("{}.{}", from, fee_hash);
        let to_cur_key = format!("{}.{}", to, asset_hash);

        match bin_to_nonce {
            // The receiver account exists.
            Ok(Some(_)) => {
                if fee_hash == asset_hash {
                    // The transaction's fee is paid in the same currency
                    // that is being transferred, so we only retrieve one
                    // balance.
                    let mut sender_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&from_cur_key.as_bytes()).unwrap(),
                            "The sender does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender balance
                    sender_balance -= self.fee.clone();

                    // Subtract amount transferred from sender balance
                    sender_balance -= self.amount.clone();

                    // The receiver account exists so we try to retrieve his balance
                    let receiver_balance: Balance = match trie.get(&to_cur_key.as_bytes()) {
                        Ok(Some(balance)) => {
                            Balance::from_bytes(&balance).unwrap() + self.amount.clone()
                        }
                        Ok(None) => self.amount.clone(),
                        Err(err) => panic!(err),
                    };

                    // Update trie
                    trie.insert(from_cur_key.as_bytes(), &sender_balance.to_bytes())
                        .unwrap();
                    trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(from_nonce_key, &from_nonce).unwrap();
                } else {
                    // The transaction's fee is paid in a different currency
                    // than the one being transferred so we retrieve both balances.
                    let mut sender_cur_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&from_cur_key.as_bytes()).unwrap(),
                            "The sender does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    let mut sender_fee_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&from_fee_key.as_bytes()).unwrap(),
                            "The sender does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender
                    sender_fee_balance -= self.fee.clone();

                    // Subtract amount transferred from sender
                    sender_cur_balance -= self.amount.clone();

                    // The receiver account exists so we try to retrieve his balance
                    let receiver_balance: Balance = match trie.get(&to_cur_key.as_bytes()) {
                        Ok(Some(balance)) => {
                            Balance::from_bytes(&balance).unwrap() + self.amount.clone()
                        }
                        Ok(None) => self.amount.clone(),
                        Err(err) => panic!(err),
                    };

                    // Update trie
                    trie.insert(from_cur_key.as_bytes(), &sender_cur_balance.to_bytes())
                        .unwrap();
                    trie.insert(from_fee_key.as_bytes(), &sender_fee_balance.to_bytes())
                        .unwrap();
                    trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(from_nonce_key, &from_nonce).unwrap();
                }
            }
            Ok(None) => {
                // The receiver account does not exist so we create it.
                //
                // This can only happen if the receiver address is a normal address.
                if let Address::Normal(_) = &self.to {
                    if fee_hash == asset_hash {
                        // The transaction's fee is paid in the same currency
                        // that is being transferred, so we only retrieve one
                        // balance.
                        let mut sender_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&from_cur_key.as_bytes()).unwrap(),
                                "The sender does not have an entry for the given currency"
                            )),
                            "Invalid stored balance format"
                        );

                        let receiver_balance = self.amount.clone();

                        // Subtract fee from sender balance
                        sender_balance -= self.fee.clone();

                        // Subtract amount transferred from sender balance
                        sender_balance -= self.amount.clone();

                        // Create new account by adding a `0` nonce entry.
                        trie.insert(&to_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                            .unwrap();

                        // Update balances
                        trie.insert(from_cur_key.as_bytes(), &sender_balance.to_bytes())
                            .unwrap();
                        trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes())
                            .unwrap();
                        trie.insert(from_nonce_key, &from_nonce).unwrap();
                    } else {
                        // The transaction's fee is paid in a different currency
                        // than the one being transferred so we retrieve both balances.
                        let mut sender_cur_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&from_cur_key.as_bytes()).unwrap(),
                                "The sender does not have an entry for the given currency"
                            )),
                            "Invalid stored balance format"
                        );

                        let mut sender_fee_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&from_fee_key.as_bytes()).unwrap(),
                                "The sender does not have an entry for the given currency"
                            )),
                            "Invalid stored balance format"
                        );

                        let receiver_balance = self.amount.clone();

                        // Subtract fee from sender
                        sender_fee_balance -= self.fee.clone();

                        // Subtract amount transferred from sender
                        sender_cur_balance -= self.amount.clone();

                        // Create new account by adding a `0` nonce entry.
                        trie.insert(&to_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                            .unwrap();

                        // Update balances
                        trie.insert(from_cur_key.as_bytes(), &sender_cur_balance.to_bytes())
                            .unwrap();
                        trie.insert(from_fee_key.as_bytes(), &sender_fee_balance.to_bytes())
                            .unwrap();
                        trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes())
                            .unwrap();
                        trie.insert(from_nonce_key, &from_nonce).unwrap();
                    }
                } else {
                    panic!("The receiving account does not exist and it's address is not a normal one!")
                }
            }
            Err(err) => panic!(err),
        }
    }

    /// Signs the transaction with the given secret key.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign(&message, &skey);

        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.from.pkey()),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(3)      - 8bits
    /// 2) Amount length            - 8bits
    /// 3) Fee length               - 8bits
    /// 4) Nonce                    - 64bits
    /// 5) From                     - 33byte binary
    /// 6) To                       - 33byte binary
    /// 7) Currency hash            - 32byte binary
    /// 8) Fee hash                 - 32byte binary
    /// 9) Signature                - 64byte binary
    /// 10) Amount                  - Binary of amount length
    /// 11) Fee                     - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let from = &self.from.to_bytes();
        let to = &self.to.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let asset_hash = &&self.asset_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();
        let nonce = &self.nonce;

        let fee_len = fee.len();
        let amount_len = amount.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.append(&mut from.to_vec());
        buffer.append(&mut to.to_vec());
        buffer.append(&mut asset_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Send, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let tx_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        if tx_type != Self::TX_TYPE {
            return Err("Bad transation type");
        }

        rdr.set_position(1);

        let amount_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad amount len");
        };

        rdr.set_position(2);

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(3);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..11).collect();

        let from = if buf.len() > 33 as usize {
            let from_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&from_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let to = if buf.len() > 33 as usize {
            let to_vec: Vec<u8> = buf.drain(..33).collect();

            match Address::from_bytes(&to_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let asset_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let fee_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64 as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_) => return Err("Bad signature"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let amount = if buf.len() > amount_len as usize {
            let amount_vec: Vec<u8> = buf.drain(..amount_len as usize).collect();

            match Balance::from_bytes(&amount_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad amount"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let fee = if buf.len() == fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad gas price"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let mut send = Send {
            from: from,
            to: to,
            fee_hash: fee_hash,
            fee: fee,
            amount: amount,
            nonce: nonce,
            asset_hash: asset_hash,
            hash: None,
            signature: Some(signature),
        };

        send.compute_hash();
        Ok(send)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &Send) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut from = obj.from.to_bytes();
    let mut to = obj.to.to_bytes();
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to sign
    buf.append(&mut from);
    buf.append(&mut to);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Send {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Send {
        let mut tx = Send {
            from: Arbitrary::arbitrary(g),
            to: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            hash: None,
            signature: Some(Arbitrary::arbitrary(g)),
        };

        tx.compute_hash();
        tx
    }
}

#[cfg(test)]
mod tests {
    extern crate test_helpers;

    use super::*;
    use account::NormalAddress;
    use crypto::Identity;

    #[test]
    fn validate() {
        let from_id = Identity::new();
        let to_id = Identity::new();
        let from_addr = Address::normal_from_pkey(*from_id.pkey());
        let from_norm_addr = NormalAddress::from_pkey(*from_id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender balance
        test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_norm_addr,
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(from_id.skey().clone());
        tx.compute_hash();

        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds() {
        let from_id = Identity::new();
        let to_id = Identity::new();
        let from_addr = Address::normal_from_pkey(*from_id.pkey());
        let from_norm_addr = NormalAddress::from_pkey(*from_id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender balance
        test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_norm_addr,
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(from_id.skey().clone());
        tx.compute_hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_different_currencies() {
        let from_id = Identity::new();
        let to_id = Identity::new();
        let from_addr = Address::normal_from_pkey(*from_id.pkey());
        let from_norm_addr = NormalAddress::from_pkey(*from_id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender balance
        test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, from_addr.clone(), fee_hash, b"10.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_norm_addr,
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(from_id.skey().clone());
        tx.compute_hash();

        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds_different_currencies() {
        let from_id = Identity::new();
        let to_id = Identity::new();
        let from_addr = Address::normal_from_pkey(*from_id.pkey());
        let from_norm_addr = NormalAddress::from_pkey(*from_id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender balance
        test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10.0");
        test_helpers::init_balance(&mut trie, from_addr.clone(), fee_hash, b"10.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_norm_addr,
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(from_id.skey().clone());
        tx.compute_hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds_for_fee_different_currencies() {
        let from_id = Identity::new();
        let to_id = Identity::new();
        let from_addr = Address::normal_from_pkey(*from_id.pkey());
        let from_norm_addr = NormalAddress::from_pkey(*from_id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender balance
        test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10.0");
        test_helpers::init_balance(&mut trie, from_addr.clone(), fee_hash, b"10.0");

        let amount = Balance::from_bytes(b"5.0").unwrap();
        let fee = Balance::from_bytes(b"20.0").unwrap();

        let mut tx = Send {
            from: from_norm_addr,
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(from_id.skey().clone());
        tx.compute_hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_zero() {
        let from_id = Identity::new();
        let to_id = Identity::new();
        let from_addr = Address::normal_from_pkey(*from_id.pkey());
        let from_norm_addr = NormalAddress::from_pkey(*from_id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender balance
        test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");

        let amount = Balance::from_bytes(b"0.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_norm_addr,
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(from_id.skey().clone());
        tx.compute_hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_creates_a_new_account() {
        let id = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(*id.pkey());
        let from_addr2 = Address::normal_from_pkey(*id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender balance
        test_helpers::init_balance(&mut trie, from_addr2, asset_hash, b"10000.0");

        let amount = Balance::from_bytes(b"100.123").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_addr.clone(),
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        // Apply transaction
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let from_nonce_key = format!("{}.n", hex::encode(&from_addr.to_bytes()));
        let to_nonce_key = format!("{}.n", hex::encode(&to_addr.to_bytes()));
        let from_nonce_key = from_nonce_key.as_bytes();
        let to_nonce_key = to_nonce_key.as_bytes();

        let bin_from_nonce = &trie.get(&from_nonce_key).unwrap().unwrap();
        let bin_to_nonce = &trie.get(&to_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let hex_asset_hash = hex::encode(&bin_asset_hash);

        let sender_balance_key =
            format!("{}.{}", hex::encode(&from_addr.to_bytes()), hex_asset_hash);
        let receiver_balance_key =
            format!("{}.{}", hex::encode(&to_addr.to_bytes()), hex_asset_hash);
        let sender_balance_key = sender_balance_key.as_bytes();
        let receiver_balance_key = receiver_balance_key.as_bytes();

        let sender_balance =
            Balance::from_bytes(&trie.get(&sender_balance_key).unwrap().unwrap()).unwrap();
        let receiver_balance =
            Balance::from_bytes(&trie.get(&receiver_balance_key).unwrap().unwrap()).unwrap();

        // Check nonces
        assert_eq!(bin_from_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bin_to_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 0]);

        // Verify that the correct amount of funds have been subtracted from the sender
        assert_eq!(
            sender_balance,
            Balance::from_bytes(b"10000.0").unwrap() - amount.clone() - fee.clone()
        );

        // Verify that the receiver has received the correct amount of funds
        assert_eq!(receiver_balance, amount);
    }

    #[test]
    fn apply_it_sends_to_an_existing_account() {
        let id = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(*id.pkey());
        let from_addr2 = Address::normal_from_pkey(*id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize sender and receiver balances
        test_helpers::init_balance(&mut trie, from_addr2, asset_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, to_addr.clone(), asset_hash, b"10.0");

        let amount = Balance::from_bytes(b"100.123").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_addr.clone(),
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        // Apply transaction
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let from_nonce_key = format!("{}.n", hex::encode(&from_addr.to_bytes()));
        let to_nonce_key = format!("{}.n", hex::encode(&to_addr.to_bytes()));
        let from_nonce_key = from_nonce_key.as_bytes();
        let to_nonce_key = to_nonce_key.as_bytes();

        let bin_from_nonce = &trie.get(&from_nonce_key).unwrap().unwrap();
        let bin_to_nonce = &trie.get(&to_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let hex_asset_hash = hex::encode(&bin_asset_hash);

        let sender_balance_key =
            format!("{}.{}", hex::encode(&from_addr.to_bytes()), hex_asset_hash);
        let receiver_balance_key =
            format!("{}.{}", hex::encode(&to_addr.to_bytes()), hex_asset_hash);
        let sender_balance_key = sender_balance_key.as_bytes();
        let receiver_balance_key = receiver_balance_key.as_bytes();

        let sender_balance =
            Balance::from_bytes(&trie.get(&sender_balance_key).unwrap().unwrap()).unwrap();
        let receiver_balance =
            Balance::from_bytes(&trie.get(&receiver_balance_key).unwrap().unwrap()).unwrap();

        // Check nonces
        assert_eq!(bin_from_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bin_to_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 0]);

        // Verify that the correct amount of funds have been subtracted from the sender
        assert_eq!(
            sender_balance,
            Balance::from_bytes(b"10000.0").unwrap() - amount.clone() - fee.clone()
        );

        // Verify that the receiver has received the correct amount of funds
        assert_eq!(
            receiver_balance,
            Balance::from_bytes(b"10.0").unwrap() + amount
        );
    }

    quickcheck! {
        fn serialize_deserialize(tx: Send) -> bool {
            tx == Send::from_bytes(&Send::to_bytes(&tx).unwrap()).unwrap()
        }

         fn verify_hash(tx: Send) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            to: Address,
            amount: Balance,
            fee: Balance,
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();

            let mut tx = Send {
                from: NormalAddress::from_pkey(*id.pkey()),
                to: to,
                amount: amount,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                nonce: 1,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
