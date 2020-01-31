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

use account::{Address, Balance, NormalAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{ShortHash, Hash, PublicKey as Pk, SecretKey as Sk, Signature};
use patricia_trie::{TrieDBMut, TrieDB, TrieMut, Trie};
use persistence::{DbHasher, Codec};
use rand::Rng;
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq)]
pub struct CreateMintable {
    pub(crate) creator: Pk,
    pub(crate) next_address: NormalAddress,
    pub(crate) receiver: Address,
    pub(crate) minter_address: Address,
    pub(crate) asset_hash: ShortHash,
    pub(crate) coin_supply: u64,
    pub(crate) max_supply: u64,
    pub(crate) precision: u8,
    pub(crate) fee_hash: ShortHash,
    pub(crate) fee: Balance,
    pub(crate) nonce: u64,
    pub(crate) hash: Option<Hash>,
    pub(crate) signature: Option<Signature>,
}

impl CreateMintable {
    pub const TX_TYPE: u8 = 5;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<DbHasher, Codec>) -> bool {
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

        // The coin supply cannot be greater or equal to the max supply
        if self.coin_supply >= self.max_supply {
            return false;
        }

        // Verify signature
        if !self.verify_sig() {
            return false;
        }

        let bin_receiver = &self.receiver.to_bytes();
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;
        let coin_supply = &self.coin_supply;
        let creator_signing_addr = NormalAddress::from_pkey(&self.creator);

        // Do not allow address re-usage
        if self.next_address == creator_signing_addr {
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
        let addr_mapping_key = [creator_signing_addr.as_bytes(), &b".am"[..]].concat();

        // Retrieve creator account permanent address
        let creator_perm_addr = match trie.get(&addr_mapping_key) {
            Ok(Some(perm_addr)) => NormalAddress::from_bytes(&perm_addr).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        // Do not allow address re-usage 
        if self.next_address == creator_perm_addr {
            return false
        }

        // Calculate precision key
        //
        // The key of a currency's precision has the following format:
        // `<currency-hash>.p`
        let asset_hash_prec_key = [bin_asset_hash, &b".p"[..]].concat();

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let creator_nonce_key = [creator_perm_addr.as_bytes(), &b".n"[..]].concat();

        // Calculate fee key
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let creator_fee_key = [creator_perm_addr.as_bytes(), &b"."[..], bin_fee_hash].concat();

        // Check if the currency already exists
        if let Ok(Some(_)) | Err(_) = trie.get(&asset_hash_prec_key) {
            return false;
        }

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

        balance >= Balance::from_bytes(b"0.0").unwrap()
    }

    /// Applies the CreateMintable transaction to the provided database.
    ///
    /// This function will panic if the `creator` account does not exist.
    pub fn apply(&self, trie: &mut TrieDBMut<DbHasher, Codec>) {
        let bin_receiver = self.receiver.as_bytes();
        let bin_minter_addr = &self.minter_address.to_bytes();
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;
        let coin_supply = &self.coin_supply;
        let max_supply = &self.max_supply;

        if bin_asset_hash == bin_fee_hash {
            panic!("The created currency hash cannot be the same as the fee hash!");
        }

        let creator_signing_addr = NormalAddress::from_pkey(&self.creator);

        // Calculate address mapping key
        //
        // An address mapping is a mapping between
        // the account's signing address and an 
        // account's receiving address.
        //
        // They key of the address mapping has the following format:
        // `<signing-address>.am`
        let creator_addr_mapping_key = [creator_signing_addr.as_bytes(), &b".am"[..]].concat();
        let next_addr_mapping_key = [self.next_address.as_bytes(), &b".am"[..]].concat();

        // Retrieve creator account permanent address
        let creator_perm_addr = trie.get(&creator_addr_mapping_key).unwrap().unwrap();
        let creator_perm_addr = NormalAddress::from_bytes(&creator_perm_addr).unwrap();

        // Calculate precision key
        //
        // The key of a currency's precision has the following format:
        // `<currency-hash>.p`
        let asset_hash_prec_key = [bin_asset_hash, &b".p"[..]].concat();

        // Calculate coin supply key
        //
        // The key of a currency's coin supply entry has the following format:
        // `<currency-hash>.s`
        let asset_hash_supply_key = [bin_asset_hash, &b".s"[..]].concat();

        // Calculate max supply key
        //
        // The key of a currency's max supply entry has the following format:
        // `<currency-hash>.s`
        let asset_hash_max_supply_key = [bin_asset_hash, &b".x"[..]].concat();

        // Calculate minter address key
        //
        // The key of a currency's minter address has the following format:
        // `<currency-hash>.m`
        let asset_hash_minter_key = [bin_asset_hash, &b".m"[..]].concat();

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let creator_nonce_key = [creator_perm_addr.as_bytes(), &b".n"[..]].concat();
        let receiver_nonce_key = [bin_receiver, &b".n"[..]].concat();

        // Retrieve serialized nonce
        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();
        let bin_receiver_nonce = trie.get(&receiver_nonce_key);

        let mut nonce_rdr = Cursor::new(bin_creator_nonce);

        // Read the nonce of the creator
        let mut nonce = nonce_rdr.read_u64::<BigEndian>().unwrap();

        // Increment creator nonce
        nonce += 1;

        let mut nonce_buf: Vec<u8> = Vec::with_capacity(8);

        // Write new nonce to buffer
        nonce_buf.write_u64::<BigEndian>(nonce).unwrap();

        let mut coin_supply_buf: Vec<u8> = Vec::with_capacity(8);

        // Write coin supply to buffer
        coin_supply_buf
            .write_u64::<BigEndian>(*coin_supply)
            .unwrap();

        let mut max_supply_buf: Vec<u8> = Vec::with_capacity(8);

        // Write max supply to buffer
        max_supply_buf.write_u64::<BigEndian>(*max_supply).unwrap();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let creator_cur_key = [creator_perm_addr.as_bytes(), &b"."[..], bin_asset_hash].concat();
        let creator_fee_key = [creator_perm_addr.as_bytes(), &b"."[..], bin_fee_hash].concat();
        let receiver_cur_key = [bin_receiver, &b"."[..], bin_asset_hash].concat();

        // The creator is the same as the receiver, so we
        // just add all the new currency to it's address.
        if creator_perm_addr.as_bytes() == bin_receiver {
            let mut creator_fee_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&creator_fee_key).unwrap(),
                    "The creator does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from sender balance
            creator_fee_balance -= self.fee.clone();

            // Calculate creator balance
            let creator_cur_balance = Balance::from_u64(self.coin_supply);

            // Update trie
            trie.insert(&asset_hash_supply_key, &coin_supply_buf)
                .unwrap();
            trie.insert(&asset_hash_minter_key, &bin_minter_addr)
                .unwrap();
            trie.insert(&asset_hash_max_supply_key, &max_supply_buf)
                .unwrap();
            trie.insert(&asset_hash_prec_key, &[self.precision]).unwrap();
            trie.insert(&creator_cur_key, &creator_cur_balance.to_bytes())
                .unwrap();
            trie.insert(&creator_fee_key, &creator_fee_balance.to_bytes())
                .unwrap();
            trie.insert(&creator_nonce_key, &nonce_buf).unwrap();

            // Update address mappings
            trie.remove(&creator_addr_mapping_key).unwrap();
            trie.insert(&next_addr_mapping_key, creator_perm_addr.as_bytes()).unwrap();
        } else {
            // The receiver is another account
            match bin_receiver_nonce {
                // The receiver account exists
                Ok(Some(_)) => {
                    let mut creator_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&creator_fee_key).unwrap(),
                            "The creator does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender balance
                    creator_balance -= self.fee.clone();

                    // Calculate receiver balance
                    let receiver_balance = Balance::from_u64(self.coin_supply);

                    // Update trie
                    trie.insert(&asset_hash_supply_key, &coin_supply_buf)
                        .unwrap();
                    trie.insert(&asset_hash_minter_key, &bin_minter_addr)
                        .unwrap();
                    trie.insert(&asset_hash_max_supply_key, &max_supply_buf)
                        .unwrap();
                    trie.insert(&asset_hash_prec_key, &[self.precision]).unwrap();
                    trie.insert(&creator_fee_key, &creator_balance.to_bytes())
                        .unwrap();
                    trie.insert(&receiver_cur_key, &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(&creator_nonce_key, &nonce_buf).unwrap();

                    // Update address mappings
                    trie.remove(&creator_addr_mapping_key).unwrap();
                    trie.insert(&next_addr_mapping_key, creator_perm_addr.as_bytes()).unwrap();
                }
                // The receiver account does not exist so we create it
                Ok(None) => {
                    let receiver_addr_mapping_key = [self.receiver.as_bytes(), &b".am"[..]].concat();
                    let mut creator_balance = unwrap!(
                        Balance::from_bytes(&unwrap!(
                            trie.get(&creator_fee_key).unwrap(),
                            "The creator does not have an entry for the given currency"
                        )),
                        "Invalid stored balance format"
                    );

                    // Subtract fee from sender balance
                    creator_balance -= self.fee.clone();

                    // Calculate receiver balance
                    let receiver_balance = Balance::from_u64(self.coin_supply);

                    // Update trie
                    trie.insert(&asset_hash_supply_key, &coin_supply_buf)
                        .unwrap();
                    trie.insert(&asset_hash_minter_key, &bin_minter_addr)
                        .unwrap();
                    trie.insert(&asset_hash_max_supply_key, &max_supply_buf)
                        .unwrap();
                    trie.insert(&asset_hash_prec_key, &[self.precision]).unwrap();
                    trie.insert(&creator_fee_key, &creator_balance.to_bytes())
                        .unwrap();
                    trie.insert(&receiver_cur_key, &receiver_balance.to_bytes())
                        .unwrap();
                    trie.insert(&creator_nonce_key, &nonce_buf).unwrap();
                    trie.insert(&receiver_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                        .unwrap();

                    // Update address mappings
                    trie.insert(&receiver_addr_mapping_key, self.receiver.as_bytes()).unwrap();
                    trie.remove(&creator_addr_mapping_key).unwrap();
                    trie.insert(&next_addr_mapping_key, creator_perm_addr.as_bytes()).unwrap();
                }
                Err(err) => panic!(err),
            }
        }
    }

    /// Signs the transaction with the given secret key.
    ///
    /// This function will panic if there already exists
    /// a signature and the address type doesn't match
    /// the signature type.
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
            Some(ref sig) => crypto::verify(&message, sig, &self.creator),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(5)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Precision            - 8bits
    /// 4) Coin supply          - 64bits
    /// 5) Max supply           - 64bits
    /// 6) Nonce                - 64bits
    /// 7) Currency flag        - 1byte (Value is 1 if currency and fee hashes are identical. Otherwise is 0)
    /// 8) Asset hash           - 8byte binary
    /// 9) Fee hash             - 8byte binary (Non-existent if currency flag is true)
    /// 10) Creator             - 33byte binary
    /// 11) Receiver            - 33byte binary
    /// 12) Next address        - 33byte binary
    /// 13) Minter address      - 33byte binary
    /// 14) Signature           - 64byte binary
    /// 15) Fee                 - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();

        let mut signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let receiver = self.receiver.to_bytes();
        let next_address = self.next_address.to_bytes();
        let minter_address = self.minter_address.to_bytes();
        let asset_hash = &self.asset_hash.0;
        let fee_hash = &self.fee_hash.0;
        let coin_supply = &self.coin_supply;
        let max_supply = &self.max_supply;
        let precision = &self.precision;
        let fee = &self.fee.to_bytes();
        let nonce = &self.nonce;
        let currency_flag = if asset_hash == fee_hash {
            1
        } else {
            0
        };

        let fee_len = fee.len();

        buffer.write_u8(Self::TX_TYPE).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u8(*precision).unwrap();
        buffer.write_u64::<BigEndian>(*coin_supply).unwrap();
        buffer.write_u64::<BigEndian>(*max_supply).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();
        buffer.write_u8(currency_flag).unwrap();
        buffer.extend_from_slice(asset_hash);

        if currency_flag == 0 {
            buffer.extend_from_slice(fee_hash);
        }

        buffer.extend_from_slice(&self.creator.0);
        buffer.extend_from_slice(&receiver);
        buffer.extend_from_slice(&next_address);
        buffer.extend_from_slice(&minter_address);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(fee);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<CreateMintable, &'static str> {
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

        let max_supply = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad max supply");
        };

        rdr.set_position(19);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        rdr.set_position(27);

        let currency_flag = if let Ok(result) = rdr.read_u8() {
            if result == 0 || result == 1 {
                result 
            } else {
                return Err("Bad currency flag value");
            }
        } else {
            return Err("Bad currency flag");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..28).collect();

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

        let creator = if buf.len() > 32 as usize {
            let creator_vec: Vec<u8> = buf.drain(..32).collect();
            let mut creator_bytes = [0; 32];

            creator_bytes.copy_from_slice(&creator_vec);
            Pk(creator_bytes)
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

        let next_address = if buf.len() > 33 as usize {
            let next_address_vec: Vec<u8> = buf.drain(..33).collect();
            NormalAddress::from_bytes(&next_address_vec)?
        } else {
            return Err("Incorrect packet structure");
        };

        let minter_address = if buf.len() > 33 as usize {
            let minter_address_vec: Vec<u8> = buf.drain(..33).collect();

            match Address::from_bytes(&minter_address_vec) {
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

        let mut create_mintable = CreateMintable {
            creator,
            receiver,
            next_address,
            coin_supply,
            fee_hash,
            minter_address,
            max_supply,
            fee,
            precision,
            asset_hash,
            nonce,
            hash: None,
            signature: Some(signature),
        };

        create_mintable.compute_hash();
        Ok(create_mintable)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<DbHasher, Codec>, sk: Sk) -> CreateMintable {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &CreateMintable) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let receiver = obj.receiver.to_bytes();
    let next_address = obj.next_address.to_bytes();
    let minter_address = obj.minter_address.to_bytes();
    let fee = obj.fee.to_bytes();
    let coin_supply = obj.coin_supply;
    let max_supply = obj.max_supply;
    let precision = obj.precision;
    let asset_hash = &obj.asset_hash.0;
    let fee_hash = &obj.fee_hash.0;

    buf.write_u8(precision).unwrap();
    buf.write_u64::<BigEndian>(coin_supply).unwrap();
    buf.write_u64::<BigEndian>(max_supply).unwrap();
    buf.write_u64::<BigEndian>(obj.nonce).unwrap();

    // Compose data to sign
    buf.extend_from_slice(&obj.creator.0);
    buf.extend_from_slice(&receiver);
    buf.extend_from_slice(&next_address);
    buf.extend_from_slice(&minter_address);
    buf.extend_from_slice(asset_hash);
    buf.extend_from_slice(fee_hash);
    buf.extend_from_slice(&fee);
    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for CreateMintable {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> CreateMintable {
        let (pk, _) = crypto::gen_keypair();
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);

        let asset_hash = Arbitrary::arbitrary(g);
        let fee_hash = if random == 1 {
            asset_hash
        } else {
            Arbitrary::arbitrary(g)
        };

        let mut tx = CreateMintable {
            creator: pk,
            next_address: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            minter_address: Arbitrary::arbitrary(g),
            asset_hash,
            coin_supply: Arbitrary::arbitrary(g),
            max_supply: Arbitrary::arbitrary(g),
            precision: Arbitrary::arbitrary(g),
            fee_hash,
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
    use crypto::Identity;

    #[test]
    fn validate() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateMintable {
            creator: id.pkey().clone(),
            next_address,
            receiver: Address::Normal(creator_addr.clone()),
            minter_address: Address::Normal(creator_addr.clone()),
            coin_supply: 100,
            max_supply: 200,
            precision: 18,
            fee: fee.clone(),
            asset_hash,
            fee_hash,
            nonce: 1,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.compute_hash();

        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();
        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_bad_prec_1() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateMintable {
            creator: id.pkey().clone(),
            next_address,
            receiver: Address::Normal(creator_addr.clone()),
            minter_address: Address::Normal(creator_addr.clone()),
            coin_supply: 100,
            max_supply: 200,
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

        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_bad_coin_supply() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateMintable {
            creator: id.pkey().clone(),
            next_address,
            receiver: Address::Normal(creator_addr.clone()),
            minter_address: Address::Normal(creator_addr.clone()),
            coin_supply: 0,
            max_supply: 10,
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

        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_bad_prec_2() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateMintable {
            creator: id.pkey().clone(),
            next_address,
            receiver: Address::Normal(creator_addr.clone()),
            minter_address: Address::Normal(creator_addr.clone()),
            coin_supply: 100,
            max_supply: 200,
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

        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_same_currencies() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateMintable {
            creator: id.pkey().clone(),
            next_address,
            receiver: Address::Normal(creator_addr.clone()),
            minter_address: Address::Normal(creator_addr.clone()),
            coin_supply: 100,
            max_supply: 200,
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

        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_no_creator() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;
        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();
        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateMintable {
            creator: id.pkey().clone(),
            next_address,
            receiver: Address::Normal(creator_addr.clone()),
            minter_address: Address::Normal(creator_addr.clone()),
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

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_greater_supply() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = CreateMintable {
            creator: id.pkey().clone(),
            next_address,
            receiver: Address::Normal(creator_addr.clone()),
            minter_address: Address::Normal(creator_addr.clone()),
            coin_supply: 200,
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

        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();
        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_creates_currencies_and_adds_them_to_the_creator() {
        let id = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let minter_addr = Address::normal_from_pkey(id3.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();
        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize creator balance
            test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");

            let mut tx = CreateMintable {
                creator: id.pkey().clone(),
                next_address,
                receiver: Address::Normal(creator_addr.clone()),
                minter_address: minter_addr.clone(),
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

        let trie = TrieDB::<DbHasher, Codec>::new(&db, &root).unwrap();

        let creator_nonce_key = [creator_addr.as_bytes(), &b".n"[..]].concat();
        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();

        let bin_asset_hash = &asset_hash.0;
        let bin_fee_hash = &fee_hash.0;
        let asset_hash_prec_key = [bin_asset_hash, &b".p"[..]].concat();
        let fee_hash_prec_key = [bin_fee_hash, &b".p"[..]].concat();
        let asset_hash_supply_key = [bin_asset_hash, &b".s"[..]].concat();
        let asset_hash_max_supply_key = [bin_asset_hash, &b".x"[..]].concat();
        let asset_hash_minter_key = [bin_asset_hash, &b".m"[..]].concat();

        let creator_cur_balance_key = [creator_addr.as_bytes(), &b"."[..], bin_asset_hash].concat();
        let creator_fee_balance_key = [creator_addr.as_bytes(), &b"."[..], bin_fee_hash].concat();

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
        assert_eq!(
            &trie.get(&asset_hash_max_supply_key).unwrap().unwrap(),
            &vec![0, 0, 0, 0, 0, 0, 0, 200]
        );

        // Check minter address
        assert_eq!(
            &trie.get(&asset_hash_minter_key).unwrap().unwrap(),
            &minter_addr.to_bytes()
        );
    }

    quickcheck! {
        fn serialize_deserialize(tx: CreateMintable) -> bool {
            tx == CreateMintable::from_bytes(&CreateMintable::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: CreateMintable) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            receiver: Address,
            minter_address: Address,
            fee: Balance,
            coin_supply: u64,
            max_supply: u64,
            precision: u8,
            asset_hash: ShortHash,
            fee_hash: ShortHash
        ) -> bool {
            let id = Identity::new();
            let id2 = Identity::new();

            let mut tx = CreateMintable {
                creator: id.pkey().clone(),
                next_address: NormalAddress::from_pkey(id2.pkey()),
                receiver: receiver,
                minter_address: minter_address,
                coin_supply: coin_supply,
                max_supply: max_supply,
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
