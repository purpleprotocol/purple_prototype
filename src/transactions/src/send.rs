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
use crypto::{ShortHash, Hash, PublicKey as Pk, SecretKey as Sk, Signature};
use patricia_trie::{TrieDBMut, TrieDB, TrieMut, Trie};
use persistence::{BlakeDbHasher, Codec};
use rand::Rng;
use std::io::Cursor;
use std::str;

#[derive(Debug, Clone, PartialEq)]
pub struct Send {
    pub(crate) from: Pk,
    pub(crate) next_address: NormalAddress,
    pub(crate) to: Address,
    pub(crate) amount: Balance,
    pub(crate) fee: Balance,
    pub(crate) asset_hash: Hash,
    pub(crate) fee_hash: Hash,
    pub(crate) nonce: u64,
    
    pub(crate) hash: Option<Hash>,
    
    pub(crate) signature: Option<Signature>,
}

impl Send {
    pub const TX_TYPE: u8 = 3;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<BlakeDbHasher, Codec>) -> bool {
        let zero = Balance::zero();

        // You cannot send 0 coins
        if self.amount == zero {
            return false;
        }

        // TODO: Signature verification should be done in batches 
        // and happen before validation.
        if !self.verify_sig() {
            return false;
        }

        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;

        let sender_signing_addr = NormalAddress::from_pkey(&self.from);

        // Do not allow address re-usage
        if self.next_address == sender_signing_addr {
            return false;
        }

        // Validate against sending to a non-existing contract address
        if let Address::Contract(ref addr) = self.to {
            let to_nonce_key = [addr.as_bytes(), &b".n"[..]].concat();

            if trie.get(&to_nonce_key).unwrap().is_none() {
                return false;
            }
        }

        // Calculate address mapping key
        //
        // An address mapping is a mapping between
        // the account's signing address and an 
        // account's receiving address.
        //
        // They key of the address mapping has the following format:
        // `<signing-address>.am`
        let addr_mapping_key = [sender_signing_addr.as_bytes(), &b".am"[..]].concat();

        // Retrieve sender account permanent address
        let permanent_addr = match trie.get(&addr_mapping_key) {
            Ok(Some(perm_addr)) => NormalAddress::from_bytes(&perm_addr).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        // Do not allow address re-usage 
        if self.next_address == permanent_addr {
            return false
        }

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<permanent-addr>.n`
        let nonce_key = [permanent_addr.as_bytes(), &b".n"[..]].concat();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<permanent-addr>.<currency-hash>`
        let cur_key = [permanent_addr.as_bytes(), &b"."[..], &bin_asset_hash[..]].concat();
        let fee_key = [permanent_addr.as_bytes(), &b"."[..], &bin_fee_hash[..]].concat();

        // Retrieve serialized nonce
        let bin_nonce = match trie.get(&nonce_key) {
            Ok(Some(nonce)) => nonce,
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        let stored_nonce = decode_be_u64!(bin_nonce).unwrap();
        if stored_nonce + 1 != self.nonce {
            return false;
        }

        if bin_fee_hash == bin_asset_hash {
            // The transaction's fee is paid in the same currency
            // that is being sent, so we only retrieve one balance.
            let mut balance = match trie.get(&cur_key) {
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
            let mut cur_balance = match trie.get(&cur_key) {
                Ok(Some(balance)) => match Balance::from_bytes(&balance) {
                    Ok(balance) => balance,
                    Err(err) => panic!(err),
                },
                Ok(None) => return false,
                Err(err) => panic!(err),
            };

            let mut fee_balance = match trie.get(&fee_key) {
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
        let bin_from = &self.from.0;
        let bin_to = &self.to.to_bytes();
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;
        let sender_signing_addr = NormalAddress::from_pkey(&self.from);

        // Calculate address mapping key
        //
        // An address mapping is a mapping between
        // the account's signing address and an 
        // account's receiving address.
        //
        // They key of the address mapping has the following format:
        // `<signing-address>.am`
        let from_addr_mapping_key = [sender_signing_addr.as_bytes(), &b".am"[..]].concat();
        let next_addr_mapping_key = [self.next_address.as_bytes(), &b".am"[..]].concat();

        // Retrieve sender account permanent address
        let from_perm_addr = trie.get(&from_addr_mapping_key).unwrap().unwrap();
        let from_perm_addr = NormalAddress::from_bytes(&from_perm_addr).unwrap();

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<permanent-addr>.n`
        let from_nonce_key = [from_perm_addr.as_bytes(), &b".n"[..]].concat();
        let to_nonce_key = [self.to.as_bytes(), &b".n"[..]].concat();

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
        let from_cur_key = &[from_perm_addr.as_bytes(), &b"."[..], &bin_asset_hash[..]].concat();
        let from_fee_key = &[from_perm_addr.as_bytes(), &b"."[..], &bin_fee_hash[..]].concat();
        let to_cur_key = &[self.to.as_bytes(), &b"."[..], &bin_asset_hash[..]].concat();

        match bin_to_nonce {
            // The receiver account exists.
            Ok(Some(_)) => {
                if bin_fee_hash == bin_asset_hash {
                    // The transaction's fee is paid in the same currency
                    // that is being transferred, so we only retrieve one
                    // balance.
                    let mut sender_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&from_cur_key).unwrap(),
                            "The sender does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender balance
                    sender_balance -= self.fee.clone();

                    // Subtract amount transferred from sender balance
                    sender_balance -= self.amount.clone();

                    // The receiver account exists so we try to retrieve his balance
                    let receiver_balance: Balance = match trie.get(&to_cur_key) {
                        Ok(Some(balance)) => {
                            Balance::from_bytes(&balance).unwrap() + self.amount.clone()
                        }
                        Ok(None) => self.amount.clone(),
                        Err(err) => panic!(err),
                    };

                    // Update trie
                    trie.insert(from_cur_key, &sender_balance.to_bytes())
                        .unwrap();
                    trie.insert(to_cur_key, &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(&from_nonce_key, &from_nonce).unwrap();

                    // Update sender address mapping
                    trie.remove(&from_addr_mapping_key).unwrap();
                    trie.insert(&next_addr_mapping_key, from_perm_addr.as_bytes()).unwrap();
                } else {
                    // The transaction's fee is paid in a different currency
                    // than the one being transferred so we retrieve both balances.
                    let mut sender_cur_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&from_cur_key).unwrap(),
                            "The sender does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    let mut sender_fee_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&from_fee_key).unwrap(),
                            "The sender does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender
                    sender_fee_balance -= self.fee.clone();

                    // Subtract amount transferred from sender
                    sender_cur_balance -= self.amount.clone();

                    // The receiver account exists so we try to retrieve his balance
                    let receiver_balance: Balance = match trie.get(&to_cur_key) {
                        Ok(Some(balance)) => {
                            Balance::from_bytes(&balance).unwrap() + self.amount.clone()
                        }
                        Ok(None) => self.amount.clone(),
                        Err(err) => panic!(err),
                    };

                    // Update trie
                    trie.insert(from_cur_key, &sender_cur_balance.to_bytes())
                        .unwrap();
                    trie.insert(from_fee_key, &sender_fee_balance.to_bytes())
                        .unwrap();
                    trie.insert(to_cur_key, &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(&from_nonce_key, &from_nonce).unwrap();

                    // Update sender address mapping
                    trie.remove(&from_addr_mapping_key).unwrap();
                    trie.insert(&next_addr_mapping_key, from_perm_addr.as_bytes()).unwrap();
                }
            }
            Ok(None) => {
                // The receiver account does not exist so we create it.
                //
                // This can only happen if the receiver address is a normal address.
                if let Address::Normal(_) = &self.to {
                    let to_addr_mapping_key = [self.to.as_bytes(), &b".am"[..]].concat();

                    if bin_fee_hash == bin_asset_hash {
                        // The transaction's fee is paid in the same currency
                        // that is being transferred, so we only retrieve one
                        // balance.
                        let mut sender_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&from_cur_key).unwrap(),
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
                        trie.insert(from_cur_key, &sender_balance.to_bytes())
                            .unwrap();
                        trie.insert(to_cur_key, &receiver_balance.to_bytes())
                            .unwrap();
                        trie.insert(&from_nonce_key, &from_nonce).unwrap();
                        trie.insert(&to_addr_mapping_key, self.to.as_bytes()).unwrap();

                        // Update sender address mapping
                        trie.remove(&from_addr_mapping_key).unwrap();
                        trie.insert(&next_addr_mapping_key, from_perm_addr.as_bytes()).unwrap();
                    } else {
                        // The transaction's fee is paid in a different currency
                        // than the one being transferred so we retrieve both balances.
                        let mut sender_cur_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&from_cur_key).unwrap(),
                                "The sender does not have an entry for the given currency"
                            )),
                            "Invalid stored balance format"
                        );

                        let mut sender_fee_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&from_fee_key).unwrap(),
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
                        trie.insert(from_cur_key, &sender_cur_balance.to_bytes())
                            .unwrap();
                        trie.insert(from_fee_key, &sender_fee_balance.to_bytes())
                            .unwrap();
                        trie.insert(to_cur_key, &receiver_balance.to_bytes())
                            .unwrap();
                        trie.insert(&from_nonce_key, &from_nonce).unwrap();
                        trie.insert(&to_addr_mapping_key, self.to.as_bytes()).unwrap();

                        // Update sender address mapping
                        trie.remove(&from_addr_mapping_key).unwrap();
                        trie.insert(&next_addr_mapping_key, from_perm_addr.as_bytes()).unwrap();
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
            Some(ref sig) => crypto::verify(&message, sig, &self.from),
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
    /// 5) From                     - 32byte binary
    /// 6) To                       - 33byte binary
    /// 7) Next address             - 33byte binary
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

        let to = self.to.as_bytes();
        let next_address = self.next_address.as_bytes();
        let amount = self.amount.to_bytes();
        let fee = self.fee.to_bytes();
        let nonce = &self.nonce;

        let fee_len = fee.len();
        let amount_len = amount.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();
        buffer.extend_from_slice(&self.from.0);
        buffer.extend_from_slice(to);
        buffer.extend_from_slice(next_address);
        buffer.extend_from_slice(&self.asset_hash.0);
        buffer.extend_from_slice(&self.fee_hash.0);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(&amount);
        buffer.extend_from_slice(&fee);

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

        let from = if buf.len() > 32 as usize {
            let from_vec: Vec<u8> = buf.drain(..32).collect();
            let mut from = [0; 32];
            from.copy_from_slice(&from_vec);

            Pk(from)
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

        let next_address = if buf.len() > 33 as usize {
            let next_address_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&next_address_vec) {
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
            from,
            to,
            next_address,
            fee_hash,
            fee,
            amount,
            nonce,
            asset_hash,
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
    let to = obj.to.as_bytes();
    let next_address = obj.next_address.as_bytes();
    let amount = obj.amount.to_bytes();
    let fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to sign
    buf.write_u64::<BigEndian>(obj.nonce).unwrap();
    buf.extend_from_slice(&obj.from.0);
    buf.extend_from_slice(to);
    buf.extend_from_slice(next_address);
    buf.extend_from_slice(&obj.asset_hash.0);
    buf.extend_from_slice(&obj.fee_hash.0);
    buf.extend_from_slice(&amount);
    buf.extend_from_slice(&fee);
    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Send {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Send {
        let (pk, _) = crypto::gen_keypair();

        let mut tx = Send {
            from: pk,
            next_address: Arbitrary::arbitrary(g),
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
    use account::{ContractAddress, NormalAddress};
    use crypto::Identity;

    #[test]
    fn validate() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = Address::normal_from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: *from_id.pkey(),
            to: to_addr.clone(),
            next_address: from_next_addr,
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

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = Address::normal_from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: *from_id.pkey(),
            to: to_addr.clone(),
            next_address: from_next_addr,
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

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_different_currencies() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = Address::normal_from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");
            test_helpers::init_balance(&mut trie, from_addr.clone(), fee_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: *from_id.pkey(),
            to: to_addr.clone(),
            next_address: from_next_addr,
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(from_id.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds_different_currencies() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = Address::normal_from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10.0");
            test_helpers::init_balance(&mut trie, from_addr.clone(), fee_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: *from_id.pkey(),
            to: to_addr.clone(),
            next_address: from_next_addr,
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

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds_for_fee_different_currencies() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = Address::normal_from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10.0");
            test_helpers::init_balance(&mut trie, from_addr.clone(), fee_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"5.0").unwrap();
        let fee = Balance::from_bytes(b"20.0").unwrap();

        let mut tx = Send {
            from: *from_id.pkey(),
            to: to_addr.clone(),
            next_address: from_next_addr,
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

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_zero() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = Address::normal_from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");
        }

        let amount = Balance::zero();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: *from_id.pkey(),
            next_address: from_next_addr,
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

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_fails_on_sending_to_non_existing_contract() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let addr_hash = crypto::hash_slice(b"test_contract");
        let to_addr = ContractAddress::new(addr_hash);
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: *from_id.pkey(),
            next_address: from_next_addr,
            to: Address::Contract(to_addr.clone()),
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

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_creates_a_new_account() {
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = Address::normal_from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();
        let amount = Balance::from_bytes(b"100.123").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender balance
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");

            let mut tx = Send {
                from: *from_id.pkey(),
                next_address: from_next_addr,
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

            // Apply transaction
            tx.apply(&mut trie);
        }

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();

        let from_nonce_key = [from_addr.as_bytes(), &b".n"[..]].concat();
        let to_nonce_key = [to_addr.as_bytes(), &b".n"[..]].concat();
        let from_addr_mapping_key = [from_addr.as_bytes(), &b".am"[..]].concat();
        let from_next_addr_mapping_key = [from_next_addr.as_bytes(), &b".am"[..]].concat();
        let to_addr_mapping_key = [to_addr.as_bytes(), &b".am"[..]].concat();

        let bin_from_nonce = &trie.get(&from_nonce_key).unwrap().unwrap();
        let bin_to_nonce = &trie.get(&to_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let sender_balance_key = [from_addr.as_bytes(), &b"."[..], &bin_asset_hash].concat();
        let receiver_balance_key = [to_addr.as_bytes(), &b"."[..], &bin_asset_hash].concat();

        let sender_balance =
            Balance::from_bytes(&trie.get(&sender_balance_key).unwrap().unwrap()).unwrap();
        let receiver_balance =
            Balance::from_bytes(&trie.get(&receiver_balance_key).unwrap().unwrap()).unwrap();

        assert_eq!(trie.get(&from_addr_mapping_key).unwrap(), None);
        let from_next_addr_mapping = trie.get(&from_next_addr_mapping_key).unwrap().unwrap();
        let to_addr_mapping = trie.get(&to_addr_mapping_key).unwrap().unwrap();

        // Check nonces
        assert_eq!(bin_from_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bin_to_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 0]);

        // Check address mappings
        assert_eq!(from_next_addr_mapping, from_addr.as_bytes());
        assert_eq!(to_addr_mapping, to_addr.as_bytes());

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
        let from_id = Identity::new();
        let from_id2 = Identity::new();
        let to_id = Identity::new();
        let from_addr = NormalAddress::from_pkey(&from_id.pkey());
        let from_next_addr = NormalAddress::from_pkey(&from_id2.pkey());
        let to_addr = NormalAddress::from_pkey(&to_id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();
        let amount = Balance::from_bytes(b"100.123").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize sender and receiver balances
            test_helpers::init_balance(&mut trie, from_addr.clone(), asset_hash, b"10000.0");
            test_helpers::init_balance(&mut trie, to_addr.clone(), asset_hash, b"10.0");

            let mut tx = Send {
                from: *from_id.pkey(),
                next_address: from_next_addr,
                to: Address::Normal(to_addr.clone()),
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

            // Apply transaction
            tx.apply(&mut trie);
        }

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();

        let from_nonce_key = [from_addr.as_bytes(), &b".n"[..]].concat();
        let to_nonce_key = [to_addr.as_bytes(), &b".n"[..]].concat();
        let from_addr_mapping_key = [from_addr.as_bytes(), &b".am"[..]].concat();
        let from_next_addr_mapping_key = [from_next_addr.as_bytes(), &b".am"[..]].concat();

        let bin_from_nonce = &trie.get(&from_nonce_key).unwrap().unwrap();
        let bin_to_nonce = &trie.get(&to_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let sender_balance_key = [from_addr.as_bytes(), &b"."[..], &bin_asset_hash].concat();
        let receiver_balance_key = [to_addr.as_bytes(), &b"."[..], &bin_asset_hash].concat();

        let sender_balance =
            Balance::from_bytes(&trie.get(&sender_balance_key).unwrap().unwrap()).unwrap();
        let receiver_balance =
            Balance::from_bytes(&trie.get(&receiver_balance_key).unwrap().unwrap()).unwrap();

        assert_eq!(trie.get(&from_addr_mapping_key).unwrap(), None);
        let from_next_addr_mapping = trie.get(&from_next_addr_mapping_key).unwrap().unwrap();

        // Check address mappings
        assert_eq!(from_next_addr_mapping, from_addr.as_bytes());

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
            next_address: NormalAddress,
            amount: Balance,
            fee: Balance,
            asset_hash: ShortHash,
            fee_hash: ShortHash
        ) -> bool {
            let id = Identity::new();

            let mut tx = Send {
                from: *id.pkey(),
                next_address,
                to,
                amount,
                fee,
                asset_hash,
                fee_hash,
                nonce: 1,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
