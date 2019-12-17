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
use crypto::{Hash, SecretKey as Sk, Signature};
use patricia_trie::{TrieDBMut, TrieDB, TrieMut, Trie};
use persistence::{BlakeDbHasher, Codec};
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateCurrency {
    pub(crate) creator: NormalAddress,
    pub(crate) receiver: Address,
    pub(crate) asset_hash: Hash,
    pub(crate) coin_supply: u64,
    pub(crate) precision: u8,
    pub(crate) fee_hash: Hash,
    pub(crate) fee: Balance,
    pub(crate) nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature: Option<Signature>,
}

impl CreateCurrency {
    pub const TX_TYPE: u8 = 4;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<BlakeDbHasher, Codec>) -> bool {
        // The created currency cannot be the same
        // as the one the fee is being paid in.
        if &self.asset_hash == &self.fee_hash {
            return false;
        }

        // The precision must be a number between 0 and 18 excluding 1.
        if self.precision > 18 || self.precision == 1 {
            return false;
        }

        // The coin supply cannot be lower than 1
        if self.coin_supply < 1 {
            return false;
        }

        // Verify signature
        if !self.verify_sig() {
            return false;
        }

        let bin_creator = &self.creator.to_bytes();
        let bin_receiver = &self.receiver.to_bytes();
        let bin_asset_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();
        let coin_supply = &self.coin_supply;

        // Convert addresses to strings
        let creator = hex::encode(bin_creator);
        let receiver = hex::encode(bin_receiver);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate precision key
        //
        // The key of a currency's precision has the following format:
        // `<currency-hash>.p`
        let asset_hash_prec_key = format!("{}.p", asset_hash);
        let asset_hash_prec_key = asset_hash_prec_key.as_bytes();

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let creator_nonce_key = format!("{}.n", creator);
        let creator_nonce_key = creator_nonce_key.as_bytes();

        // Calculate fee key
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let creator_fee_key = format!("{}.{}", creator, fee_hash);
        let creator_fee_key = creator_fee_key.as_bytes();

        // Retrieve serialized nonce
        let bin_creator_nonce = match trie.get(&creator_nonce_key) {
            Ok(Some(nonce)) => nonce,
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        // Retrieve serialized balance
        let bin_creator_balance = match trie.get(&creator_fee_key) {
            Ok(Some(nonce)) => nonce,
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        // Read the nonce of the creator
        let nonce = decode_be_u64!(bin_creator_nonce).unwrap();

        // Read the fee balance of the creator
        let mut balance = Balance::from_bytes(&bin_creator_balance).unwrap();

        balance -= self.fee.clone();

        if nonce + 1 != self.nonce {
            return false;
        }

        // Check if the currency already exists
        if let Ok(Some(_)) = trie.get(asset_hash_prec_key) {
            return false;
        }

        balance >= Balance::from_bytes(b"0.0").unwrap()
    }

    /// Applies the CreateCurrency transaction to the provided database.
    ///
    /// This function will panic if the `creator` account does not exist.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_creator = &self.creator.to_bytes();
        let bin_receiver = &self.receiver.to_bytes();
        let bin_asset_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();
        let coin_supply = &self.coin_supply;

        // Convert addresses to strings
        let creator = hex::encode(bin_creator);
        let receiver = hex::encode(bin_receiver);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        if asset_hash == fee_hash {
            panic!("The created currency hash cannot be the same as the fee hash!");
        }

        // Calculate precision key
        //
        // The key of a currency's precision has the following format:
        // `<currency-hash>.p`
        let asset_hash_prec_key = format!("{}.p", asset_hash);
        let asset_hash_prec_key = asset_hash_prec_key.as_bytes();

        // Calculate coin supply key
        //
        // The key of a currency's coin supply entry has the following format:
        // `<currency-hash>.s`
        let asset_hash_supply_key = format!("{}.s", asset_hash);
        let asset_hash_supply_key = asset_hash_supply_key.as_bytes();

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let creator_nonce_key = format!("{}.n", creator);
        let creator_nonce_key = creator_nonce_key.as_bytes();
        let receiver_nonce_key = format!("{}.n", receiver);
        let receiver_nonce_key = receiver_nonce_key.as_bytes();

        // Retrieve serialized nonce
        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();
        let bin_receiver_nonce = trie.get(&receiver_nonce_key);

        // Read the nonce of the creator
        let mut nonce = decode_be_u64!(bin_creator_nonce).unwrap();

        // Increment creator nonce
        nonce += 1;

        let nonce: Vec<u8> = encode_be_u64!(nonce);
        let coin_supply: Vec<u8> = encode_be_u64!(*coin_supply);

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let creator_cur_key = format!("{}.{}", creator, asset_hash);
        let creator_fee_key = format!("{}.{}", creator, fee_hash);
        let receiver_cur_key = format!("{}.{}", receiver, asset_hash);

        // The creator is the same as the receiver, so we
        // just add all the new currency to it's address.
        if bin_creator == bin_receiver {
            let mut creator_fee_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&creator_fee_key.as_bytes()).unwrap(),
                    "The creator does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from sender balance
            creator_fee_balance -= self.fee.clone();

            // Calculate creator balance
            let creator_cur_balance = format!("{}.0", self.coin_supply);
            let creator_cur_balance = Balance::from_bytes(creator_cur_balance.as_bytes()).unwrap();

            // Update trie
            trie.insert(asset_hash_supply_key, &coin_supply).unwrap();
            trie.insert(asset_hash_prec_key, &[self.precision]).unwrap();
            trie.insert(creator_cur_key.as_bytes(), &creator_cur_balance.to_bytes())
                .unwrap();
            trie.insert(creator_fee_key.as_bytes(), &creator_fee_balance.to_bytes())
                .unwrap();
            trie.insert(creator_nonce_key, &nonce).unwrap();
        } else {
            // The receiver is another account
            match bin_receiver_nonce {
                // The receiver account exists
                Ok(Some(_)) => {
                    let mut creator_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&creator_fee_key.as_bytes()).unwrap(),
                            "The creator does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender balance
                    creator_balance -= self.fee.clone();

                    // Calculate receiver balance
                    let receiver_balance = format!("{}.0", self.coin_supply);
                    let receiver_balance =
                        Balance::from_bytes(receiver_balance.as_bytes()).unwrap();

                    // Update trie
                    trie.insert(asset_hash_supply_key, &coin_supply).unwrap();
                    trie.insert(asset_hash_prec_key, &[self.precision]).unwrap();
                    trie.insert(creator_fee_key.as_bytes(), &creator_balance.to_bytes())
                        .unwrap();
                    trie.insert(receiver_cur_key.as_bytes(), &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(creator_nonce_key, &nonce).unwrap();
                }
                // The receiver account does not exist so we create it
                Ok(None) => {
                    let mut creator_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&creator_fee_key.as_bytes()).unwrap(),
                            "The creator does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender balance
                    creator_balance -= self.fee.clone();

                    // Calculate receiver balance
                    let receiver_balance = format!("{}.0", self.coin_supply);
                    let receiver_balance =
                        Balance::from_bytes(receiver_balance.as_bytes()).unwrap();

                    // Update trie
                    trie.insert(asset_hash_supply_key, &coin_supply).unwrap();
                    trie.insert(asset_hash_prec_key, &[self.precision]).unwrap();
                    trie.insert(creator_fee_key.as_bytes(), &creator_balance.to_bytes())
                        .unwrap();
                    trie.insert(receiver_cur_key.as_bytes(), &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(creator_nonce_key, &nonce).unwrap();
                    trie.insert(receiver_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                        .unwrap();
                }
                Err(err) => panic!(err),
            }
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
            Some(ref sig) => crypto::verify(&message, sig, &self.creator.pkey()),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(8)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Precision            - 8bits
    /// 4) Coin supply          - 64bits
    /// 5) Nonce                - 64bits
    /// 6) Creator              - 33byte binary
    /// 7) Receiver             - 33byte binary
    /// 8) Currency hash        - 32byte binary
    /// 9) Fee hash             - 32byte binary
    /// 10) Signature           - 65byte binary
    /// 11) Fee                 - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let mut signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let creator = &self.creator.to_bytes();
        let receiver = &self.receiver.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let coin_supply = &self.coin_supply;
        let precision = &self.precision;
        let fee = &self.fee.to_bytes();
        let nonce = &self.nonce;

        let fee_len = fee.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u8(*precision).unwrap();
        buffer.write_u64::<BigEndian>(*coin_supply).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.append(&mut creator.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut asset_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut signature);
        buffer.append(&mut fee.to_vec());

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<CreateCurrency, &'static str> {
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

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(2);

        let precision = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad precision");
        };

        rdr.set_position(3);

        let coin_supply = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad coin supply");
        };

        rdr.set_position(11);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..19).collect();

        let creator = if buf.len() > 33 as usize {
            let creator_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&creator_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 33 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..33).collect();

            match Address::from_bytes(&receiver_vec) {
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
            let sig_vec: Vec<u8> = buf.drain(..64).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_) => return Err("Bad signature"),
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

        let mut create_currency = CreateCurrency {
            creator: creator,
            receiver: receiver,
            coin_supply: coin_supply,
            fee_hash: fee_hash,
            fee: fee,
            precision: precision,
            asset_hash: asset_hash,
            nonce: nonce,
            hash: None,
            signature: Some(signature),
        };

        create_currency.compute_hash();
        Ok(create_currency)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> CreateCurrency {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &CreateCurrency) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let precision = obj.precision;
    let coin_supply = obj.coin_supply;
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    buf.write_u8(precision).unwrap();
    buf.write_u64::<BigEndian>(coin_supply).unwrap();

    // Compose data to sign
    buf.append(&mut creator);
    buf.append(&mut receiver);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for CreateCurrency {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> CreateCurrency {
        let mut tx = CreateCurrency {
            creator: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            coin_supply: Arbitrary::arbitrary(g),
            precision: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
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
    use crypto::Identity;

    #[test]
    fn validate() {
        let id = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateCurrency {
            creator: creator_norm_address.clone(),
            receiver: creator_addr.clone(),
            coin_supply: 100,
            precision: 18,
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_bad_prec_1() {
        let id = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }


        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateCurrency {
            creator: creator_norm_address.clone(),
            receiver: creator_addr.clone(),
            coin_supply: 100,
            precision: 19,
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_bad_coin_supply() {
        let id = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateCurrency {
            creator: creator_norm_address.clone(),
            receiver: creator_addr.clone(),
            coin_supply: 0,
            precision: 15,
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_bad_prec_2() {
        let id = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateCurrency {
            creator: creator_norm_address.clone(),
            receiver: creator_addr.clone(),
            coin_supply: 100,
            precision: 1,
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_same_currencies() {
        let id = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateCurrency {
            creator: creator_norm_address.clone(),
            receiver: creator_addr.clone(),
            coin_supply: 100,
            precision: 18,
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_no_creator() {
        let id = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateCurrency {
            creator: creator_norm_address.clone(),
            receiver: creator_addr.clone(),
            coin_supply: 100,
            precision: 18,
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_creates_currencies_and_adds_them_to_the_creator() {
        let id = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");
        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");

            let mut tx = CreateCurrency {
                creator: creator_norm_address.clone(),
                receiver: creator_addr.clone(),
                coin_supply: 100,
                precision: 18,
                fee: fee.clone(),
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                nonce: 1,
                signature: None,
                hash: None,
            };

            tx.sign(id.skey().clone());
            tx.compute_hash();

            // Apply transaction
            tx.apply(&mut trie);
        }

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();

        let creator_nonce_key = format!("{}.n", hex::encode(&creator_addr.to_bytes()));
        let creator_nonce_key = creator_nonce_key.as_bytes();

        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let bin_fee_hash = fee_hash.to_vec();
        let hex_asset_hash = hex::encode(&bin_asset_hash);
        let hex_fee_hash = hex::encode(&bin_fee_hash);
        let asset_hash_prec_key = format!("{}.p", hex_asset_hash);
        let asset_hash_prec_key = asset_hash_prec_key.as_bytes();
        let fee_hash_prec_key = format!("{}.p", hex_fee_hash);
        let fee_hash_prec_key = fee_hash_prec_key.as_bytes();
        let asset_hash_supply_key = format!("{}.s", hex_asset_hash);
        let asset_hash_supply_key = asset_hash_supply_key.as_bytes();

        let creator_cur_balance_key = format!(
            "{}.{}",
            hex::encode(&creator_addr.to_bytes()),
            hex_asset_hash
        );
        let creator_cur_balance_key = creator_cur_balance_key.as_bytes();
        let creator_fee_balance_key =
            format!("{}.{}", hex::encode(&creator_addr.to_bytes()), hex_fee_hash);
        let creator_fee_balance_key = creator_fee_balance_key.as_bytes();

        let creator_fee_balance =
            Balance::from_bytes(&trie.get(&creator_fee_balance_key).unwrap().unwrap()).unwrap();
        let creator_cur_balance =
            Balance::from_bytes(&trie.get(&creator_cur_balance_key).unwrap().unwrap()).unwrap();

        // Check nonce
        assert_eq!(bin_creator_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);

        // Check balances
        assert_eq!(
            creator_fee_balance,
            Balance::from_bytes(b"10000.0").unwrap() - fee.clone()
        );
        assert_eq!(creator_cur_balance, amount.clone());

        // Check currencies precisions
        assert_eq!(&trie.get(&asset_hash_prec_key).unwrap().unwrap(), &vec![18]);
        assert_eq!(&trie.get(&fee_hash_prec_key).unwrap().unwrap(), &vec![18]);

        // Check currency supply
        assert_eq!(
            &trie.get(&asset_hash_supply_key).unwrap().unwrap(),
            &vec![0, 0, 0, 0, 0, 0, 0, 100]
        );
    }

    // #[test]
    // fn apply_it_creates_currencies_and_adds_them_to_a_receiver() {

    // }

    quickcheck! {
        fn serialize_deserialize(tx: CreateCurrency) -> bool {
            tx == CreateCurrency::from_bytes(&CreateCurrency::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: CreateCurrency) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            receiver: Address,
            fee: Balance,
            coin_supply: u64,
            precision: u8,
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();

            let mut tx = CreateCurrency {
                creator: NormalAddress::from_pkey(*id.pkey()),
                receiver: receiver,
                coin_supply: coin_supply,
                precision: precision,
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
