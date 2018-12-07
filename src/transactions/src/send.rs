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

use std::str;
use account::{Address, Balance, Signature, ShareMap, MultiSig, NormalAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, PublicKey as Pk, SecretKey as Sk};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use hashdb::HashDB;
use patricia_trie::{TrieMut, TrieDBMut, NodeCodec};
use elastic_array::ElasticArray128;
use persistence::{BlakeDbHasher, Codec};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Send {
    from: Address,
    to: Address,
    amount: Balance,
    fee: Balance,
    currency_hash: Hash,
    fee_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl Send {
    pub const TX_TYPE: u8 = 3;

    /// Applies the send transaction to the provided database.
    ///
    /// This function will panic if the `from` account does not exist.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_from = &self.from.to_bytes();
        let bin_to = &self.to.to_bytes();
        let bin_cur_hash = &self.currency_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();

        // Convert addresses to strings
        let from = hex::encode(bin_from);
        let to = hex::encode(bin_to);

        // Convert hashes to strings
        let cur_hash = hex::encode(bin_cur_hash);
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

        let mut from_nonce_rdr = Cursor::new(bin_from_nonce);

        // Read the nonce of the sender
        let mut from_nonce = from_nonce_rdr.read_u64::<BigEndian>().unwrap();

        // Increment sender nonce
        from_nonce += 1;

        let mut from_nonce_buf: Vec<u8> = Vec::with_capacity(8);

        // Write new nonce to buffer
        from_nonce_buf.write_u64::<BigEndian>(from_nonce).unwrap();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let from_cur_key = format!("{}.{}", from, cur_hash);
        let from_fee_key = format!("{}.{}", from, fee_hash);
        let to_cur_key = format!("{}.{}", to, cur_hash);

        match bin_to_nonce {
            // The receiver account exists.
            Ok(Some(_)) => { 
                if fee_hash == cur_hash {
                    // The transaction's fee is paid in the same currency
                    // that is being transferred, so we only retrieve one
                    // balance.
                    let mut sender_balance = unwrap!(
                        Balance::from_bytes(
                            &unwrap!(
                                trie.get(&from_cur_key.as_bytes()).unwrap(),
                                "The sender does not have an entry for the given currency"
                            )
                        ),
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
                        },
                        Ok(None) => {
                            self.amount.clone()
                        },
                        Err(err) => panic!(err)
                    };

                    // Update trie
                    trie.insert(from_cur_key.as_bytes(), &sender_balance.to_bytes()).unwrap();
                    trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
                    trie.insert(from_nonce_key, &from_nonce_buf).unwrap();
                } else {
                    // The transaction's fee is paid in a different currency
                    // than the one being transferred so we retrieve both balances.
                    let mut sender_cur_balance = unwrap!(
                        Balance::from_bytes(
                            &unwrap!(
                                trie.get(&from_cur_key.as_bytes()).unwrap(),
                                "The sender does not have an entry for the given currency"
                            )
                        ),
                        "Invalid stored balance format"
                    );

                    let mut sender_fee_balance = unwrap!(
                        Balance::from_bytes(
                            &unwrap!(
                                trie.get(&from_fee_key.as_bytes()).unwrap(),
                                "The sender does not have an entry for the given currency"
                            )
                        ),
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
                        },
                        Ok(None) => {
                            self.amount.clone()
                        },
                        Err(err) => panic!(err)
                    };

                    // Update trie
                    trie.insert(from_cur_key.as_bytes(), &sender_cur_balance.to_bytes()).unwrap();
                    trie.insert(from_fee_key.as_bytes(), &sender_fee_balance.to_bytes()).unwrap();
                    trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
                    trie.insert(from_nonce_key, &from_nonce_buf).unwrap();
                }
            },
            Ok(None) => {
                // The receiver account does not exist so we create it.
                // 
                // This can only happen if the receiver address is a normal address.
                if let Address::Normal(_) = &self.to {
                    if fee_hash == cur_hash {
                        // The transaction's fee is paid in the same currency
                        // that is being transferred, so we only retrieve one
                        // balance.
                        let mut sender_balance = unwrap!(
                            Balance::from_bytes(
                                &unwrap!(
                                    trie.get(&from_cur_key.as_bytes()).unwrap(),
                                    "The sender does not have an entry for the given currency"
                                )
                            ),
                            "Invalid stored balance format"
                        );

                        let receiver_balance = self.amount.clone();

                        // Subtract fee from sender balance
                        sender_balance -= self.fee.clone();

                        // Subtract amount transferred from sender balance
                        sender_balance -= self.amount.clone();

                        // Create new account by adding a `0` nonce entry.
                        trie.insert(&to_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

                        // Update balances
                        trie.insert(from_cur_key.as_bytes(), &sender_balance.to_bytes()).unwrap();
                        trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
                        trie.insert(from_nonce_key, &from_nonce_buf).unwrap();
                    } else {
                        // The transaction's fee is paid in a different currency
                        // than the one being transferred so we retrieve both balances.
                        let mut sender_cur_balance = unwrap!(
                            Balance::from_bytes(
                                &unwrap!(
                                    trie.get(&from_cur_key.as_bytes()).unwrap(),
                                    "The sender does not have an entry for the given currency"
                                )
                            ),
                            "Invalid stored balance format"
                        );

                        let mut sender_fee_balance = unwrap!(
                            Balance::from_bytes(
                                &unwrap!(
                                    trie.get(&from_fee_key.as_bytes()).unwrap(),
                                    "The sender does not have an entry for the given currency"
                                )
                            ),
                            "Invalid stored balance format"
                        );

                        let receiver_balance = self.amount.clone();

                        // Subtract fee from sender
                        sender_fee_balance -= self.fee.clone();

                        // Subtract amount transferred from sender
                        sender_cur_balance -= self.amount.clone();

                        // Create new account by adding a `0` nonce entry.
                        trie.insert(&to_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

                        // Update balances
                        trie.insert(from_cur_key.as_bytes(), &sender_cur_balance.to_bytes()).unwrap();
                        trie.insert(from_fee_key.as_bytes(), &sender_fee_balance.to_bytes()).unwrap();
                        trie.insert(to_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
                        trie.insert(from_nonce_key, &from_nonce_buf).unwrap();
                    }
                } else {
                    panic!("The receiving account does not exist and it's address is not a normal one!")
                }
            },
            Err(err) => panic!(err) 
        }
    }

    /// Signs the transaction with the given secret key.
    ///
    /// This function will panic if there already exists
    /// a signature and the address type doesn't match
    /// the signature type.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        match self.signature {
            Some(Signature::Normal(_)) => { 
                if let Address::Normal(_) = self.from {
                    let result = Signature::Normal(signature);
                    self.signature = Some(result);
                } else {
                    panic!("Invalid address type");
                }
            },
            Some(Signature::MultiSig(ref mut sig)) => {
                if let Address::Normal(_) = self.from {
                    panic!("Invalid address type");
                } else {
                    // Append signature to the multi sig struct
                    sig.append_sig(signature);
                }           
            },
            None => {
                if let Address::Normal(_) = self.from {
                    // Create a normal signature
                    let result = Signature::Normal(signature);
                    
                    // Attach signature to struct
                    self.signature = Some(result);
                } else {
                    // Create a multi signature
                    let result = Signature::MultiSig(MultiSig::from_sig(signature));

                    // Attach signature to struct
                    self.signature = Some(result);
                }
            }
        };
    }
    
    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    ///
    /// This function panics if the transaction has a multi 
    /// signature attached to it or if the signer's address
    /// is not a normal address.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(Signature::Normal(ref sig)) => { 
                if let Address::Normal(ref addr) = self.from {
                    crypto::verify(&message, sig.clone(), addr.pkey())
                } else {
                    panic!("The address of the signer is not a normal address!");
                }
            },
            Some(Signature::MultiSig(_)) => {
                panic!("Calling this function on a multi signature transaction is not permitted!");
            },
            None => {
                false
            }
        }
    }

    /// Verifies the multi signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    ///
    /// This function panics if the transaction has a multi 
    /// signature attached to it or if the signer's address
    /// is not a normal address.
    pub fn verify_multi_sig(&mut self, required_keys: u8, pkeys: &[Pk]) -> bool {
        if pkeys.len() < required_keys as usize {
            false
        } else {
            let message = assemble_sign_message(&self);

            match self.signature {
                Some(Signature::Normal(_)) => { 
                    panic!("Calling this function on a transaction with a normal signature is not permitted!");
                },
                Some(Signature::MultiSig(ref sig)) => {
                    sig.verify(&message, required_keys, pkeys)
                },
                None => {
                    false
                }
            }
        }
    }

    /// Verifies the multi signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_multi_sig_shares(&mut self, required_percentile: u8, share_map: ShareMap) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(Signature::Normal(_)) => { 
                panic!("Calling this function on a transaction with a normal signature is not permitted!");
            },
            Some(Signature::MultiSig(ref sig)) => {
                sig.verify_shares(&message, required_percentile, share_map)
            },
            None => {
                false
            }
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(3)      - 8bits
    /// 2) Amount length            - 8bits
    /// 3) Fee length               - 8bits
    /// 4) Signature length         - 16bits
    /// 5) From                     - 33byte binary
    /// 6) To                       - 33byte binary
    /// 7) Currency hash            - 32byte binary
    /// 8) Fee hash                 - 32byte binary
    /// 9) Hash                     - 32byte binary
    /// 10) Signature               - Binary of signature length
    /// 11) Amount                  - Binary of amount length
    /// 12) Fee                     - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let hash = if let Some(hash) = &self.hash {
            &hash.0
        } else {
            return Err("Hash field is missing");
        };

        let signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let from = &self.from.to_bytes();
        let to = &self.to.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let currency_hash = &&self.currency_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();
        let amount_len = amount.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();

        buffer.append(&mut from.to_vec());
        buffer.append(&mut to.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
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

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
        };

        // Consume cursor
        let mut buf = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..5).collect();

        let from = if buf.len() > 33 as usize {
            let from_vec: Vec<u8> = buf.drain(..33).collect();
            
            match Address::from_bytes(&from_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let to = if buf.len() > 33 as usize {
            let to_vec: Vec<u8> = buf.drain(..33).collect();
            
            match Address::from_bytes(&to_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let currency_hash = if buf.len() > 32 as usize {
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

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() > signature_len as usize {
            let sig_vec: Vec<u8> = buf.drain(..signature_len as usize).collect();
            
            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_)  => return Err("Bad signature")
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let amount = if buf.len() > amount_len as usize {
            let amount_vec: Vec<u8> = buf.drain(..amount_len as usize).collect();
            
            match Balance::from_bytes(&amount_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad amount")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let fee = if buf.len() == fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();
            
            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad gas price")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let send = Send {
            from: from,
            to: to,
            fee_hash: fee_hash,
            fee: fee,
            amount: amount,
            currency_hash: currency_hash,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(send)
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &Send) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut from = obj.from.to_bytes();
    let mut to = obj.to.to_bytes();
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let currency_hash = obj.currency_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to hash
    buf.append(&mut from);
    buf.append(&mut to);
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &Send) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut from = obj.from.to_bytes();
    let mut to = obj.to.to_bytes();
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let currency_hash = obj.currency_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to sign
    buf.append(&mut from);
    buf.append(&mut to);
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Send {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Send {
        Send {
            from: Arbitrary::arbitrary(g),
            to: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;
    use hashdb::Hasher;
    use tempfile::tempdir;
    use persistence::PersistentDb;
    use std::sync::Arc;
    use kvdb_rocksdb::{Database, DatabaseConfig};

    #[test]
    fn apply_it_creates_a_new_account() {
        let id = Identity::new();
        let to_id = Identity::new();
        let from_addr = Address::normal_from_pkey(*id.pkey());
        let to_addr = Address::normal_from_pkey(*to_id.pkey());
        let cur_hash = crypto::hash_slice(b"Test currency");

        let mut db = init_tempdb();
        let mut root = Hash::null_rlp();

        // Manually insert null root
        let _ = db.insert(&root.to_vec());

        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::from_existing(&mut db, &mut root).unwrap();

        // Manually initialize sender balance
        init_balance(&mut trie, from_addr.clone(), cur_hash, b"10000.0");

        let amount = Balance::from_bytes(b"100.123").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Send {
            from: from_addr.clone(),
            to: to_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            currency_hash: cur_hash,
            fee_hash: cur_hash,
            signature: None,
            hash: None
        };

        tx.sign(id.skey().clone());
        tx.hash();

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

        let bin_cur_hash = cur_hash.to_vec();
        let hex_cur_hash = hex::encode(&bin_cur_hash);

        let sender_balance_key = format!("{}.{}", hex::encode(&from_addr.to_bytes()), hex_cur_hash);
        let receiver_balance_key = format!("{}.{}", hex::encode(&to_addr.to_bytes()), hex_cur_hash);
        let sender_balance_key = sender_balance_key.as_bytes();
        let receiver_balance_key = receiver_balance_key.as_bytes();

        let sender_balance = Balance::from_bytes(&trie.get(&sender_balance_key).unwrap().unwrap()).unwrap();
        let receiver_balance = Balance::from_bytes(&trie.get(&receiver_balance_key).unwrap().unwrap()).unwrap();

        // Check nonces
        assert_eq!(bin_from_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bin_to_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0]);

        // Verify that the correct amount of funds have been subtracted from the sender
        assert_eq!(sender_balance, Balance::from_bytes(b"10000.0").unwrap() - amount.clone() - fee.clone());

        // Verify that the receiver has received the correct amount of funds
        assert_eq!(receiver_balance, amount);
    }

    fn init_tempdb() -> PersistentDb {
        let config = DatabaseConfig::with_columns(None);
        let dir = tempdir().unwrap();
        let db = Database::open(&config, dir.path().to_str().unwrap()).unwrap();
        let db_ref = Arc::new(db);

        PersistentDb::new(db_ref, None)
    }

    fn init_balance(
        trie: &mut TrieDBMut<BlakeDbHasher, Codec>,
        address: Address,
        currency_hash: Hash,
        amount: &[u8]
    ) {
        let bin_address = address.to_bytes();
        let bin_cur_hash = currency_hash.to_vec();

        let hex_address = hex::encode(&bin_address);
        let hex_cur_hash = hex::encode(&bin_cur_hash);

        let cur_key = format!("{}.{}", hex_address, hex_cur_hash);
        let nonce_key = format!("{}.n", hex_address);

        // Re-serialize balance to validate with regex
        let balance = Balance::from_bytes(amount).unwrap().to_bytes();

        trie.insert(&cur_key.as_bytes(), &balance).unwrap();
        trie.insert(&nonce_key.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        trie.commit();
    }

    quickcheck! {
        fn serialize_deserialize(tx: Send) -> bool {
            tx == Send::from_bytes(&Send::to_bytes(&tx).unwrap()).unwrap()
        }

         fn verify_hash(tx: Send) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            to: Address,
            amount: Balance,
            fee: Balance,
            currency_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();

            let mut tx = Send {
                from: Address::normal_from_pkey(*id.pkey()),
                to: to,
                amount: amount,
                fee: fee,
                currency_hash: currency_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }

        fn verify_multi_signature(
            to: Address,
            amount: Balance,
            fee: Balance,
            currency_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let mut ids: Vec<Identity> = (0..30)
                .into_iter()
                .map(|_| Identity::new())
                .collect();

            let creator_id = ids.pop().unwrap();
            let pkeys: Vec<Pk> = ids
                .iter()
                .map(|i| *i.pkey())
                .collect();

            let mut tx = Send {
                from: Address::multi_sig_from_pkeys(&pkeys, *creator_id.pkey(), 4314),
                to: to,
                amount: amount,
                fee: fee,
                currency_hash: currency_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            // Sign using each identity
            for id in ids {
                tx.sign(id.skey().clone());
            }
            
            tx.verify_multi_sig(10, &pkeys)
        }

        fn verify_multi_signature_shares(
            to: Address,
            amount: Balance,
            fee: Balance,
            currency_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let mut ids: Vec<Identity> = (0..30)
                .into_iter()
                .map(|_| Identity::new())
                .collect();

            let creator_id = ids.pop().unwrap();
            let pkeys: Vec<Pk> = ids
                .iter()
                .map(|i| *i.pkey())
                .collect();

            let addresses: Vec<NormalAddress> = pkeys
                .iter()
                .map(|pk| NormalAddress::from_pkey(*pk))
                .collect();
            
            let mut share_map = ShareMap::new(); 

            for addr in addresses.clone() {
                share_map.add_shareholder(addr, 100);
            }

            let mut tx = Send {
                from: Address::shareholders_from_pkeys(&pkeys, *creator_id.pkey(), 4314),
                to: to,
                amount: amount,
                fee: fee,
                currency_hash: currency_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            // Sign using each identity
            for id in ids {
                tx.sign(id.skey().clone());
            }
            
            tx.verify_multi_sig_shares(10, share_map)
        }
    }
}