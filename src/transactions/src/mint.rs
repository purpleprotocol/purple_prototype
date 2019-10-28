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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Mint {
    minter: NormalAddress,
    receiver: Address,
    amount: Balance,
    asset_hash: Hash,
    fee_hash: Hash,
    fee: Balance,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl Mint {
    pub const TX_TYPE: u8 = 6;

    /// Validates the transaction against the provided state.
    pub fn validate(&mut self, trie: &TrieDBMut<BlakeDbHasher, Codec>) -> bool {
        let zero = Balance::from_bytes(b"0.0").unwrap();

        // You cannot mint 0 tokens
        if self.amount == zero {
            return false;
        }

        if !self.verify_sig() {
            return false;
        }

        let bin_minter = &self.minter.to_bytes();
        let bin_receiver = &self.receiver.to_bytes();
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;

        // Convert addresses to strings
        let minter = hex::encode(bin_minter);
        let receiver = hex::encode(bin_receiver);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate coin supply key
        //
        // The key of a currency's coin supply entry has the following format:
        // `<currency-hash>.s`
        let coin_supply_key = format!("{}.s", asset_hash);
        let coin_supply_key = coin_supply_key.as_bytes();

        // Calculate max supply key
        //
        // The key of a currency's max supply entry has the following format:
        // `<currency-hash>.s`
        let max_supply_key = format!("{}.x", asset_hash);
        let max_supply_key = max_supply_key.as_bytes();

        let minter_addr_key = format!("{}.m", asset_hash);
        let minter_addr_key = minter_addr_key.as_bytes();

        // Check nonce
        let minter_nonce_key = format!("{}.n", minter);
        let minter_nonce_key = minter_nonce_key.as_bytes();

        let bin_minter_nonce = trie.get(&minter_nonce_key);

        let next_nonce = match bin_minter_nonce {
            Ok(Some(nonce)) => {
                let mut nonce = decode_be_u64!(nonce).unwrap();
                nonce += 1;

                nonce
            }
            Ok(None) => decode_be_u64!(vec![0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            Err(err) => panic!(err),
        };

        if next_nonce != self.nonce {
            return false;
        }

        // Check for currency existence
        let _ = match trie.get(&minter_addr_key) {
            Ok(Some(stored_minter)) => {
                // Check minter validity
                if &stored_minter.to_vec() != &bin_minter.to_vec() {
                    return false;
                }
            }
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        let coin_supply = trie.get(&coin_supply_key).unwrap().unwrap();
        let coin_supply = decode_be_u64!(coin_supply).unwrap();
        let coin_supply = format!("{}.0", coin_supply);
        let coin_supply = coin_supply.as_bytes();
        let mut coin_supply = Balance::from_bytes(coin_supply).unwrap();

        let max_supply = trie.get(&max_supply_key).unwrap().unwrap();
        let max_supply = decode_be_u64!(max_supply).unwrap();
        let max_supply = format!("{}.0", max_supply);
        let max_supply = max_supply.as_bytes();
        let max_supply = Balance::from_bytes(max_supply).unwrap();

        coin_supply += self.amount.clone();

        // Validate minted amount
        if coin_supply > max_supply {
            return false;
        }

        let minter_fee_key = format!("{}.{}", minter, fee_hash);
        let minter_fee_key = minter_fee_key.as_bytes();
        let precision_key = format!("{}.p", asset_hash);
        let precision_key = precision_key.as_bytes();

        // Check for currency existence
        let _ = match trie.get(precision_key) {
            Ok(Some(result)) => result,
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        let mut balance = match trie.get(minter_fee_key) {
            Ok(Some(balance)) => Balance::from_bytes(&balance).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        balance -= self.fee.clone();
        balance >= zero
    }

    /// Applies the mint transaction to the provided database.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_minter = &self.minter.to_bytes();
        let bin_receiver = &self.receiver.to_bytes();
        let bin_asset_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();

        // Convert addresses to strings
        let minter = hex::encode(bin_minter);
        let receiver = hex::encode(bin_receiver);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        let minter_cur_key = format!("{}.{}", minter, asset_hash);
        let minter_cur_key = minter_cur_key.as_bytes();
        let minter_fee_key = format!("{}.{}", minter, fee_hash);
        let minter_fee_key = minter_fee_key.as_bytes();
        let receiver_cur_key = format!("{}.{}", receiver, asset_hash);
        let receiver_cur_key = receiver_cur_key.as_bytes();

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let minter_nonce_key = format!("{}.n", minter);
        let minter_nonce_key = minter_nonce_key.as_bytes();
        let receiver_nonce_key = format!("{}.n", receiver);
        let receiver_nonce_key = receiver_nonce_key.as_bytes();

        // Retrieve serialized nonce
        let bin_minter_nonce = trie.get(&minter_nonce_key);
        let bin_receiver_nonce = trie.get(&receiver_nonce_key);

        // Create minter account if it doesn't exist
        let nonce: Vec<u8> = match bin_minter_nonce {
            Ok(Some(nonce)) => {
                // Read the nonce of the minter
                let mut nonce = decode_be_u64!(nonce).unwrap();

                // Increment minter nonce
                nonce += 1;

                encode_be_u64!(nonce)
            }
            Ok(None) => vec![0, 0, 0, 0, 0, 0, 0, 0],
            Err(err) => panic!(err),
        };

        match bin_receiver_nonce {
            // The receiver account exists
            Ok(Some(_)) => {
                if minter == receiver {
                    if asset_hash == fee_hash {
                        let mut minter_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&minter_cur_key).unwrap(),
                                "The minter does not have an entry for the given currency"
                            )),
                            "Invalid stored balance format"
                        );

                        // Subtract fee from minter balance
                        minter_balance -= self.fee.clone();

                        // Add minted amount to minter balance
                        minter_balance += self.amount.clone();

                        // Update trie
                        trie.insert(&minter_nonce_key, &nonce).unwrap();
                        trie.insert(&minter_cur_key, &minter_balance.to_bytes())
                            .unwrap();
                    } else {
                        let mut minter_fee_balance = unwrap!(
                            Balance::from_bytes(&unwrap!(
                                trie.get(&minter_fee_key).unwrap(),
                                "The minter does not have an entry for the given currency"
                            )),
                            "Invalid stored balance format"
                        );

                        // Subtract fee from minter balance
                        minter_fee_balance -= self.fee.clone();

                        let minter_balance: Balance = match trie.get(&minter_cur_key) {
                            Ok(Some(balance)) => {
                                Balance::from_bytes(&balance).unwrap() + self.amount.clone()
                            }
                            Ok(None) => self.amount.clone(),
                            Err(err) => panic!(err),
                        };

                        // Update trie
                        trie.insert(&minter_nonce_key, &nonce).unwrap();
                        trie.insert(&minter_cur_key, &minter_balance.to_bytes())
                            .unwrap();
                        trie.insert(&minter_fee_key, &minter_fee_balance.to_bytes())
                            .unwrap();
                    }
                } else {
                    let mut minter_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&minter_fee_key).unwrap(),
                            "The minter does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from minter balance
                    minter_balance -= self.fee.clone();

                    // The receiver account exists so we try to retrieve his balance
                    let receiver_balance: Balance = match trie.get(&receiver_cur_key) {
                        Ok(Some(balance)) => {
                            Balance::from_bytes(&balance).unwrap() + self.amount.clone()
                        }
                        Ok(None) => self.amount.clone(),
                        Err(err) => panic!(err),
                    };

                    // Update trie
                    trie.insert(&minter_nonce_key, &nonce).unwrap();
                    trie.insert(&minter_fee_key, &minter_balance.to_bytes())
                        .unwrap();
                    trie.insert(&receiver_cur_key, &receiver_balance.to_bytes())
                        .unwrap();
                }
            }
            // The receiver account doesn't exist so we create it
            Ok(None) => {
                let mut minter_balance = unwrap!(
                    Balance::from_bytes(&unwrap!(
                        trie.get(&minter_cur_key).unwrap(),
                        "The minter does not have an entry for the given currency"
                    )),
                    "Invalid stored balance format"
                );

                // Subtract fee from minter balance
                minter_balance -= self.fee.clone();

                // Update trie
                trie.insert(&minter_nonce_key, &nonce).unwrap();
                trie.insert(&receiver_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                trie.insert(&minter_cur_key, &minter_balance.to_bytes())
                    .unwrap();
                trie.insert(&receiver_cur_key, &self.amount.to_bytes())
                    .unwrap();
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
            Some(ref sig) => crypto::verify(&message, sig, &self.minter.pkey()),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(10)     - 8bits
    /// 2) Fee length               - 8bits
    /// 3) Amount length            - 8bits
    /// 4) Signature length         - 16bits
    /// 5) Nonce                    - 64bits
    /// 6) Minter                   - 33byte binary
    /// 7) Receiver                 - 33byte binary
    /// 8) Currency hash            - 32byte binary
    /// 9) Fee hash                 - 32byte binary
    /// 10) Hash                    - 32byte binary
    /// 11) Signature               - 64byte binary
    /// 12) Amount                  - Binary of amount length
    /// 13) Fee                     - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let hash = if let Some(hash) = &self.hash {
            &hash.0
        } else {
            return Err("Hash field is missing");
        };

        let mut signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let minter = &self.minter.to_bytes();
        let receiver = &self.receiver.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();
        let nonce = &self.nonce;

        let fee_len = fee.len();
        let amount_len = amount.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.append(&mut minter.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut asset_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature);
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Mint, &'static str> {
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

        let amount_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad amount len");
        };

        rdr.set_position(3);

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
        };

        rdr.set_position(5);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..13).collect();

        let minter = if buf.len() > 33 as usize {
            let minter_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&minter_vec) {
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

        let hash = if buf.len() > 32 as usize {
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
                Err(err) => return Err(err),
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
                Err(_) => return Err("Bad fee"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let mint = Mint {
            minter: minter,
            receiver: receiver,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            fee: fee,
            amount: amount,
            nonce: nonce,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(mint)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &Mint) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut minter = obj.minter.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let asset_hash = &obj.asset_hash.0;
    let fee_hash = &obj.fee_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();

    // Compose data to hash
    buf.append(&mut minter);
    buf.append(&mut receiver);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Mint {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Mint {
        Mint {
            minter: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use account::NormalAddress;
    use create_currency::CreateCurrency;
    use crypto::Identity;
    use CreateMintable;

    #[test]
    fn validate() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        // Create mintable token
        let mut create_mintable = CreateMintable {
            creator: creator_norm_address,
            receiver: creator_addr,
            minter_address: minter_addr,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            coin_supply: 10000,
            max_supply: 100000000,
            precision: 18,
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        create_mintable.sign(id2.skey().clone());
        create_mintable.hash();
        create_mintable.apply(&mut trie);

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: creator_addr,
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_exceeds_max_supply() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        // Create mintable token
        let mut create_mintable = CreateMintable {
            creator: creator_norm_address,
            receiver: creator_addr,
            minter_address: minter_addr,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            coin_supply: 9999,
            max_supply: 10000,
            precision: 18,
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        create_mintable.sign(id2.skey().clone());
        create_mintable.hash();
        create_mintable.apply(&mut trie);

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: creator_addr,
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_it_fails_on_zero_tokens() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        // Create mintable token
        let mut create_mintable = CreateMintable {
            creator: creator_norm_address,
            receiver: creator_addr,
            minter_address: minter_addr,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            coin_supply: 100,
            max_supply: 10000,
            precision: 18,
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        create_mintable.sign(id2.skey().clone());
        create_mintable.hash();
        create_mintable.apply(&mut trie);

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: creator_addr,
            amount: Balance::from_bytes(b"0.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_not_existing() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: creator_addr,
            amount: Balance::from_bytes(b"10.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_it_fails_on_trying_to_a_mint_non_mintable_currency() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        // Create mintable token
        let mut create_mintable = CreateCurrency {
            creator: creator_norm_address,
            receiver: creator_addr,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            coin_supply: 100,
            precision: 18,
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        create_mintable.sign(id2.skey().clone());
        create_mintable.hash();
        create_mintable.apply(&mut trie);

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: creator_addr,
            amount: Balance::from_bytes(b"10.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_mints_tokens_and_adds_them_to_the_creator() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        // Create mintable token
        let mut create_mintable = CreateMintable {
            creator: creator_norm_address,
            receiver: creator_addr,
            minter_address: minter_addr,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            coin_supply: 10000,
            max_supply: 100000000,
            precision: 18,
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        create_mintable.sign(id2.skey().clone());
        create_mintable.hash();
        create_mintable.apply(&mut trie);

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: creator_addr,
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let asset_hash = hex::encode(asset_hash.to_vec());
        let fee_hash = hex::encode(fee_hash.to_vec());
        let address = hex::encode(creator_addr.to_bytes());
        let minter = hex::encode(minter_addr.to_bytes());

        let cur_key = format!("{}.{}", address, asset_hash);
        let cur_key = cur_key.as_bytes();
        let fee_key = format!("{}.{}", address, fee_hash);
        let fee_key = fee_key.as_bytes();
        let minter_fee_key = format!("{}.{}", minter, fee_hash);
        let minter_fee_key = minter_fee_key.as_bytes();
        let creator_nonce_key = format!("{}.n", address);
        let creator_nonce_key = creator_nonce_key.as_bytes();
        let minter_nonce_key = format!("{}.n", minter);
        let minter_nonce_key = minter_nonce_key.as_bytes();

        let cur_balance = trie.get(&cur_key).unwrap().unwrap();
        let fee_balance = trie.get(&fee_key).unwrap().unwrap();
        let minter_balance = trie.get(&minter_fee_key).unwrap().unwrap();
        let creator_nonce = trie.get(&creator_nonce_key).unwrap().unwrap();
        let minter_nonce = trie.get(&minter_nonce_key).unwrap().unwrap();

        assert_eq!(
            cur_balance,
            Balance::from_bytes(b"10100.0").unwrap().to_bytes()
        );
        assert_eq!(
            fee_balance,
            Balance::from_bytes(b"9970.0").unwrap().to_bytes()
        );
        assert_eq!(
            minter_balance,
            Balance::from_bytes(b"90.0").unwrap().to_bytes()
        );
        assert_eq!(&creator_nonce.to_vec(), &[0, 0, 0, 0, 0, 0, 0, 1].to_vec());
        assert_eq!(&minter_nonce.to_vec(), &[0, 0, 0, 0, 0, 0, 0, 1].to_vec());
    }

    #[test]
    fn apply_it_mints_tokens_and_adds_them_to_the_minter() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        // Create mintable token
        let mut create_mintable = CreateMintable {
            creator: creator_norm_address,
            receiver: creator_addr,
            minter_address: minter_addr,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            coin_supply: 10000,
            max_supply: 100000000,
            precision: 18,
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        create_mintable.sign(id2.skey().clone());
        create_mintable.hash();
        create_mintable.apply(&mut trie);

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: minter_addr,
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let asset_hash = hex::encode(asset_hash.to_vec());
        let fee_hash = hex::encode(fee_hash.to_vec());
        let address = hex::encode(creator_addr.to_bytes());
        let minter = hex::encode(minter_addr.to_bytes());

        let cur_key = format!("{}.{}", minter, asset_hash);
        let cur_key = cur_key.as_bytes();
        let fee_key = format!("{}.{}", address, fee_hash);
        let fee_key = fee_key.as_bytes();
        let minter_fee_key = format!("{}.{}", minter, fee_hash);
        let minter_fee_key = minter_fee_key.as_bytes();
        let creator_nonce_key = format!("{}.n", address);
        let creator_nonce_key = creator_nonce_key.as_bytes();
        let minter_nonce_key = format!("{}.n", minter);
        let minter_nonce_key = minter_nonce_key.as_bytes();

        let cur_balance = trie.get(&cur_key).unwrap().unwrap();
        let fee_balance = trie.get(&fee_key).unwrap().unwrap();
        let minter_balance = trie.get(&minter_fee_key).unwrap().unwrap();
        let creator_nonce = trie.get(&creator_nonce_key).unwrap().unwrap();
        let minter_nonce = trie.get(&minter_nonce_key).unwrap().unwrap();

        assert_eq!(
            cur_balance,
            Balance::from_bytes(b"100.0").unwrap().to_bytes()
        );
        assert_eq!(
            fee_balance,
            Balance::from_bytes(b"9970.0").unwrap().to_bytes()
        );
        assert_eq!(
            minter_balance,
            Balance::from_bytes(b"90.0").unwrap().to_bytes()
        );
        assert_eq!(&creator_nonce.to_vec(), &[0, 0, 0, 0, 0, 0, 0, 1].to_vec());
        assert_eq!(&minter_nonce.to_vec(), &[0, 0, 0, 0, 0, 0, 0, 1].to_vec());
    }

    #[test]
    fn apply_it_mints_tokens_and_adds_them_to_the_minter_same_currency() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let minter_addr = Address::normal_from_pkey(*id2.pkey());
        let minter_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator and minter balances
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, minter_addr.clone(), fee_hash, b"100.0");

        // Create mintable token
        let mut create_mintable = CreateMintable {
            creator: creator_norm_address,
            receiver: minter_addr,
            minter_address: minter_addr,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            coin_supply: 10000,
            max_supply: 100000000,
            precision: 18,
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        create_mintable.sign(id2.skey().clone());
        create_mintable.hash();
        create_mintable.apply(&mut trie);

        let mut tx = Mint {
            minter: minter_norm_addr,
            receiver: minter_addr,
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let asset_hash = hex::encode(asset_hash.to_vec());
        let fee_hash = hex::encode(fee_hash.to_vec());
        let address = hex::encode(creator_addr.to_bytes());
        let minter = hex::encode(minter_addr.to_bytes());

        let cur_key = format!("{}.{}", minter, asset_hash);
        let cur_key = cur_key.as_bytes();
        let fee_key = format!("{}.{}", address, fee_hash);
        let fee_key = fee_key.as_bytes();
        let creator_nonce_key = format!("{}.n", address);
        let creator_nonce_key = creator_nonce_key.as_bytes();
        let minter_nonce_key = format!("{}.n", minter);
        let minter_nonce_key = minter_nonce_key.as_bytes();

        let cur_balance = trie.get(&cur_key).unwrap().unwrap();
        let fee_balance = trie.get(&fee_key).unwrap().unwrap();
        let creator_nonce = trie.get(&creator_nonce_key).unwrap().unwrap();
        let minter_nonce = trie.get(&minter_nonce_key).unwrap().unwrap();

        assert_eq!(
            cur_balance,
            Balance::from_bytes(b"10090.0").unwrap().to_bytes()
        );
        assert_eq!(
            fee_balance,
            Balance::from_bytes(b"9970.0").unwrap().to_bytes()
        );
        assert_eq!(&creator_nonce.to_vec(), &[0, 0, 0, 0, 0, 0, 0, 1].to_vec());
        assert_eq!(&minter_nonce.to_vec(), &[0, 0, 0, 0, 0, 0, 0, 1].to_vec());
    }

    quickcheck! {
        fn serialize_deserialize(tx: Mint) -> bool {
            tx == Mint::from_bytes(&Mint::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: Mint) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            receiver: Address,
            amount: Balance,
            fee: Balance,
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();

            let mut tx = Mint {
                minter: NormalAddress::from_pkey(*id.pkey()),
                receiver: receiver,
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
