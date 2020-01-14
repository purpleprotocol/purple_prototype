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
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq)]
pub struct ChangeMinter {
    /// The current minter
    pub(crate) minter: Pk,

    /// The minter's next address
    pub(crate) next_address: NormalAddress,

    /// The address of the new minter
    pub(crate) new_minter: Address,

    /// The global identifier of the mintable asset
    pub(crate) asset_hash: ShortHash,

    /// The global identifier of the asset in which
    /// the transaction fee is paid in.
    pub(crate) fee_hash: ShortHash,

    /// The transaction's fee
    pub(crate) fee: Balance,

    /// Nonce
    pub(crate) nonce: u64,

    /// Transaction hash
    pub(crate) hash: Option<Hash>,
    
    /// Transaction signature
    pub(crate) signature: Option<Signature>,
}

impl ChangeMinter {
    pub const TX_TYPE: u8 = 8;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<BlakeDbHasher, Codec>) -> bool {
        let zero = Balance::zero();

        if !self.verify_sig() {
            return false;
        }

        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;
        let minter_signing_addr = NormalAddress::from_pkey(&self.minter);

        // Do not allow address re-usage
        if self.next_address == minter_signing_addr {
            return false;
        }

        // Calculate address mapping key
        //
        // An address mapping is a mapping between
        // the account's signing address and an 
        // account's receiving address.
        //
        // They key of the address mapping has the following format:
        // `<signing-address>.am`
        let addr_mapping_key = [minter_signing_addr.as_bytes(), &b".am"[..]].concat();

        // Retrieve minter account permanent address
        let permanent_addr = match trie.get(&addr_mapping_key) {
            Ok(Some(perm_addr)) => NormalAddress::from_bytes(&perm_addr).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        // Do not allow address re-usage 
        if self.next_address == permanent_addr {
            return false
        }

        // Check nonce
        let minter_nonce_key = [permanent_addr.as_bytes(), &b".n"[..]].concat();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let fee_key = [permanent_addr.as_bytes(), &b"."[..], bin_fee_hash].concat();

        // Calculate minter address key
        //
        // The key of a currency's minter address has the following format:
        // `<currency-hash>.m`
        let asset_hash_minter_key = [bin_asset_hash, &b".m"[..]].concat();

        let minter_addr = match trie.get(&asset_hash_minter_key) {
            Ok(Some(minter)) => Address::from_bytes(&minter).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        // Validate current minter
        if minter_addr != Address::Normal(permanent_addr) {
            return false;
        }

        if self.new_minter == minter_addr {
            return false;
        }

        // Retrieve serialized nonce
        let bin_nonce = match trie.get(&minter_nonce_key) {
            Ok(Some(nonce)) => nonce,
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        let stored_nonce = decode_be_u64!(bin_nonce).unwrap();
        if stored_nonce + 1 != self.nonce {
            return false;
        }

        let mut minter_fee_balance = unwrap!(
            Balance::from_bytes(&unwrap!(
                trie.get(&fee_key).unwrap(),
                "The minter does not have an entry for the given currency"
            )),
            "Invalid stored balance format"
        );

        // Subtract fee from minter balance
        minter_fee_balance -= self.fee.clone();
        minter_fee_balance >= zero
    }

    /// Applies the change minter transaction to the provided database.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_new_minter = self.new_minter.as_bytes();
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;
        let minter_signing_addr = NormalAddress::from_pkey(&self.minter);

        // Calculate address mapping key
        //
        // An address mapping is a mapping between
        // the account's signing address and an 
        // account's receiving address.
        //
        // They key of the address mapping has the following format:
        // `<signing-address>.am`
        let minter_addr_mapping_key = [minter_signing_addr.as_bytes(), &b".am"[..]].concat();
        let next_addr_mapping_key = [self.next_address.as_bytes(), &b".am"[..]].concat();

        // Retrieve minter account permanent address
        let minter_perm_addr = trie.get(&minter_addr_mapping_key).unwrap().unwrap();
        let minter_perm_addr = NormalAddress::from_bytes(&minter_perm_addr).unwrap();

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let minter_nonce_key = [minter_perm_addr.as_bytes(), &b".n"[..]].concat();
        let new_minter_nonce_key = [bin_new_minter, &b".n"[..]].concat();

        // Handle nonce
        // Retrieve serialized nonce
        let bin_minter_nonce = &trie.get(&minter_nonce_key).unwrap().unwrap();
        let bin_new_minter_nonce = trie.get(&new_minter_nonce_key);

        let mut nonce_rdr = Cursor::new(bin_minter_nonce);

        // Read the nonce of the minter
        let mut nonce = nonce_rdr.read_u64::<BigEndian>().unwrap();

        // Increment minter nonce
        nonce += 1;

        // Create nonce buffer
        let mut nonce_buf: Vec<u8> = Vec::with_capacity(8);

        // Write new nonce to buffer
        nonce_buf.write_u64::<BigEndian>(nonce).unwrap();

        // Calculate minter address key
        //
        // The key of a currency's minter address has the following format:
        // `<currency-hash>.m`
        let asset_hash_minter_key = [bin_asset_hash, &b".m"[..]].concat();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let minter_fee_key = [minter_perm_addr.as_bytes(), &b"."[..], bin_fee_hash].concat();

        match bin_new_minter_nonce {
            // The new minter account exists
            Ok(Some(_)) => {
                let mut minter_fee_balance = unwrap!(
                    Balance::from_bytes(&unwrap!(
                        trie.get(&minter_fee_key).unwrap(),
                        "The minter does not have an entry for the given currency"
                    )),
                    "Invalid stored balance format"
                );

                // Subtract fee from minter balance
                minter_fee_balance -= self.fee.clone();

                // Update trie
                trie.insert(&asset_hash_minter_key, &bin_new_minter).unwrap();
                trie.insert(&minter_nonce_key, &nonce_buf).unwrap();
                trie.insert(&minter_fee_key, &minter_fee_balance.to_bytes())
                    .unwrap();

                // Update address mappings
                trie.remove(&minter_addr_mapping_key).unwrap();
                trie.insert(&next_addr_mapping_key, minter_perm_addr.as_bytes()).unwrap();
            }
            // The new minter account doesn't exist, so we create it
            Ok(None) => {
                let new_minter_addr_mapping_key = [self.new_minter.as_bytes(), &b".am"[..]].concat();
                let mut minter_fee_balance = unwrap!(
                    Balance::from_bytes(&unwrap!(
                        trie.get(&minter_fee_key).unwrap(),
                        "The minter does not have an entry for the given currency"
                    )),
                    "Invalid stored balance format"
                );

                // Subtract fee from minter balance
                minter_fee_balance -= self.fee.clone();

                // Update trie
                trie.insert(&minter_nonce_key, &nonce_buf).unwrap();
                trie.insert(&new_minter_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                trie.insert(&asset_hash_minter_key, &bin_new_minter).unwrap();
                trie.insert(&minter_fee_key, &minter_fee_balance.to_bytes())
                    .unwrap();

                // Update address mappings
                trie.insert(&new_minter_addr_mapping_key, self.new_minter.as_bytes()).unwrap();
                trie.remove(&minter_addr_mapping_key).unwrap();
                trie.insert(&next_addr_mapping_key, minter_perm_addr.as_bytes()).unwrap();
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
            Some(ref sig) => crypto::verify(&message, sig, &self.minter),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(8)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Nonce                - 64bits
    /// 4) Currency flag        - 1byte (Value is 1 if currency and fee hashes are identical. Otherwise is 0)
    /// 5) Asset hash           - 8byte binary
    /// 6) Fee hash             - 8byte binary (Non-existent if currency flag is true)
    /// 7) Minter               - 32byte binary
    /// 8) New Minter           - 33byte binary
    /// 9) Fee hash             - 32byte binary
    /// 10) Signature           - 64byte binary
    /// 11) Fee                 - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();

        let mut signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let tx_type: u8 = Self::TX_TYPE;
        let new_minter = &self.new_minter.to_bytes();
        let next_address = &self.next_address.to_bytes();
        let asset_hash = &self.asset_hash.0;
        let fee_hash = &self.fee_hash.0;
        let fee = &self.fee.to_bytes();
        let fee_len = fee.len();
        let nonce = &self.nonce;
        let currency_flag = if asset_hash == fee_hash {
            1
        } else {
            0
        };

        // Write to buffer
        buf.write_u8(tx_type).unwrap();
        buf.write_u8(fee_len as u8).unwrap();
        buf.write_u64::<BigEndian>(*nonce).unwrap();
        buffer.write_u8(currency_flag);
        buffer.extend_from_slice(asset_hash);

        if currency_flag == 0 {
            buffer.extend_from_slice(fee_hash);
        }

        buf.extend_from_slice(&self.minter.0);
        buf.extend_from_slice(new_minter);
        buf.extend_from_slice(next_address);
        buf.extend_from_slice(&signature);
        buf.extend_from_slice(&fee);

        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ChangeMinter, &'static str> {
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

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        rdr.set_position(3);

        let currency_flag = if let Ok(result) = rdr.read_u8() {
            if result == 0 || result == 1 {
                result 
            } else {
                return Err("Bad currency flag value");
            }
        } else {
            return Err("Bad currency flag");
        };

        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..11).collect();

        let asset_hash = if buf.len() > 8 as usize {
            let mut hash = [0; 8];
            let hash_vec: Vec<u8> = buf.drain(..8).collect();

            hash.copy_from_slice(&hash_vec);

            ShortHash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let fee_hash = if currency_flag == 1 {
            asset_hash
        } else {
            if buf.len() > 8 as usize {
                let mut hash = [0; 8];
                let hash_vec: Vec<u8> = buf.drain(..8).collect();

                hash.copy_from_slice(&hash_vec);

                ShortHash(hash)
            } else {
                return Err("Incorrect packet structure");
            }
        };

        let minter = if buf.len() > 32 as usize {
            let minter_vec: Vec<u8> = buf.drain(..32).collect();
            let mut minter_bytes = [0; 32];

            minter_bytes.copy_from_slice(&minter_vec);
            Pk(minter_bytes)
        } else {
            return Err("Incorrect packet structure");
        };

        let new_minter = if buf.len() > 33 as usize {
            let new_minter_vec: Vec<u8> = buf.drain(..33).collect();

            match Address::from_bytes(&new_minter_vec) {
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

        let mut change_minter = ChangeMinter {
            minter,
            new_minter,
            next_address,
            asset_hash,
            fee_hash,
            fee,
            nonce,
            hash: None,
            signature: Some(signature),
        };

        change_minter.compute_hash();
        Ok(change_minter)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &ChangeMinter) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let new_minter = obj.new_minter.to_bytes();
    let next_address = obj.next_address.to_bytes();
    let fee = obj.fee.to_bytes();
    let asset_hash = &obj.asset_hash.0;
    let fee_hash = &obj.fee_hash.0;

    // Compose data to hash
    buf.write_u64::<BigEndian>(obj.nonce).unwrap();
    buf.extend_from_slice(&obj.minter.0);
    buf.extend_from_slice(&new_minter);
    buf.extend_from_slice(&next_address);
    buf.extend_from_slice(asset_hash);
    buf.extend_from_slice(fee_hash);
    buf.extend_from_slice(&fee);
    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for ChangeMinter {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ChangeMinter {
        let (pk, _) = crypto::gen_keypair();
        let mut tx = ChangeMinter {
            minter: pk,
            next_address: Arbitrary::arbitrary(g),
            new_minter: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
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
    use super::*;
    use crate::CreateMintable;
    use account::NormalAddress;
    use crypto::Identity;

    #[test]
    fn validate() {
        let id = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();
        let id4 = Identity::new();
        let minter_address = NormalAddress::from_pkey(id.pkey());
        let new_minter_addr = Address::normal_from_pkey(id2.pkey());
        let next_address1 = NormalAddress::from_pkey(id3.pkey());
        let next_address2 = NormalAddress::from_pkey(id4.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize minter balance
            test_helpers::init_balance(&mut trie, minter_address.clone(), fee_hash, b"100.0");
        
            // Create mintable token
            let mut create_mintable = CreateMintable {
                creator: id.pkey().clone(),
                receiver: Address::Normal(minter_address),
                minter_address: Address::Normal(minter_address),
                next_address: next_address1,
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

            create_mintable.sign(id.skey().clone());
            create_mintable.compute_hash();
            create_mintable.apply(&mut trie);
        }

        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = ChangeMinter {
            minter: id3.pkey().clone(),
            new_minter: new_minter_addr.clone(),
            next_address: next_address2,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            fee: fee.clone(),
            nonce: 2,
            signature: None,
            hash: None,
        };

        tx.sign(id3.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_fails_on_same_minter() {
        let id = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();
        let id4 = Identity::new();
        let minter_address = NormalAddress::from_pkey(id.pkey());
        let new_minter_addr = Address::normal_from_pkey(id2.pkey());
        let next_address1 = NormalAddress::from_pkey(id3.pkey());
        let next_address2 = NormalAddress::from_pkey(id4.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize minter balance
            test_helpers::init_balance(&mut trie, minter_address.clone(), fee_hash, b"100.0");
        
            // Create mintable token
            let mut create_mintable = CreateMintable {
                creator: id.pkey().clone(),
                receiver: Address::Normal(minter_address),
                minter_address: Address::Normal(minter_address),
                next_address: next_address1,
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

            create_mintable.sign(id.skey().clone());
            create_mintable.compute_hash();
            create_mintable.apply(&mut trie);
        }

        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = ChangeMinter {
            minter: id.pkey().clone(),
            new_minter: new_minter_addr.clone(),
            next_address: next_address2,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            fee: fee.clone(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id3.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_cannot_pay_fee() {
        let id = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();
        let id4 = Identity::new();
        let minter_address = NormalAddress::from_pkey(id.pkey());
        let new_minter_addr = Address::normal_from_pkey(id2.pkey());
        let next_address1 = NormalAddress::from_pkey(id3.pkey());
        let next_address2 = NormalAddress::from_pkey(id4.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize minter balance
            test_helpers::init_balance(&mut trie, minter_address.clone(), fee_hash, b"100.0");
        
            // Create mintable token
            let mut create_mintable = CreateMintable {
                creator: id.pkey().clone(),
                receiver: Address::Normal(minter_address),
                minter_address: Address::Normal(minter_address),
                next_address: next_address1,
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

            create_mintable.sign(id.skey().clone());
            create_mintable.compute_hash();
            create_mintable.apply(&mut trie);
        }

        let fee = Balance::from_bytes(b"1000.0").unwrap();

        let mut tx = ChangeMinter {
            minter: id.pkey().clone(),
            new_minter: new_minter_addr.clone(),
            next_address: next_address2,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            fee: fee.clone(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id3.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_no_minter() {
        let id = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();
        let minter_address = NormalAddress::from_pkey(id.pkey());
        let new_minter_addr = Address::normal_from_pkey(id2.pkey());
        let next_address = NormalAddress::from_pkey(id3.pkey());

        let db = test_helpers::init_tempdb();
        let root = Hash::NULL_RLP;
        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();

        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = ChangeMinter {
            minter: id.pkey().clone(),
            new_minter: new_minter_addr.clone(),
            next_address,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            fee: fee.clone(),
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_changes_minter() {
        // Create Mintable first
        let id = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();
        let id4 = Identity::new();
        let minter_address = NormalAddress::from_pkey(id.pkey());
        let new_minter_addr = Address::normal_from_pkey(id2.pkey());
        let next_address1 = NormalAddress::from_pkey(id3.pkey());
        let next_address2 = NormalAddress::from_pkey(id4.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, minter_address.clone(), fee_hash, b"100.0");

            let mut tx = CreateMintable {
                creator: id.pkey().clone(),
                receiver: Address::Normal(minter_address.clone()),
                minter_address: Address::Normal(minter_address.clone()),
                next_address: next_address1,
                coin_supply: 100,
                max_supply: 200,
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

        let bin_asset_hash = &asset_hash.0;
        let asset_hash_minter_key = [bin_asset_hash, &b".m"[..]].concat();
        let id5 = Identity::new();
        let new_minter_addr = Address::normal_from_pkey(id5.pkey());

        {
            let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();

            // Check minter address
            assert_eq!(
                &trie.get(&asset_hash_minter_key).unwrap().unwrap(),
                &minter_address.to_bytes()
            );

            assert_ne!(
                &trie.get(&asset_hash_minter_key).unwrap().unwrap(),
                &new_minter_addr.to_bytes()
            );
        }

        {
            let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::from_existing(&mut db, &mut root).unwrap();
            let mut tx = ChangeMinter {
                minter: id3.pkey().clone(),
                new_minter: new_minter_addr.clone(),
                next_address: next_address2,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                fee: fee.clone(),
                nonce: 2,
                signature: None,
                hash: None,
            };

            tx.sign(id3.skey().clone());
            tx.compute_hash();

            // Apply transaction
            tx.apply(&mut trie);
        }

        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&db, &root).unwrap();

        // Check minter address
        assert_ne!(
            &trie.get(&asset_hash_minter_key).unwrap().unwrap(),
            &minter_address.to_bytes()
        );

        assert_eq!(
            &trie.get(&asset_hash_minter_key).unwrap().unwrap(),
            &new_minter_addr.to_bytes()
        );
    }

    quickcheck! {
        fn serialize_deserialize(tx: ChangeMinter) -> bool {
            tx == ChangeMinter::from_bytes(&ChangeMinter::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: ChangeMinter) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            new_minter: Address,
            fee: Balance,
            asset_hash: ShortHash,
            fee_hash: ShortHash
        ) -> bool {
            let id = Identity::new();
            let id2 = Identity::new();

            let mut tx = ChangeMinter {
                minter: id.pkey().clone(),
                next_address: NormalAddress::from_pkey(id2.pkey()),
                new_minter: new_minter,
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
