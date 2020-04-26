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

use account::{Balance, NormalAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, ShortHash, Signature};
use crypto::{PublicKey as Pk, SecretKey as Sk};
use patricia_trie::{Trie, TrieDB, TrieDBMut, TrieMut};
use persistence::{Codec, DbHasher};
use rand::Rng;
use std::io::Cursor;
use std::str;

#[derive(Clone, PartialEq, Debug)]
pub struct Burn {
    pub(crate) burner: Pk,
    pub(crate) next_address: NormalAddress,
    pub(crate) amount: Balance,
    pub(crate) fee: Balance,
    pub(crate) asset_hash: ShortHash,
    pub(crate) fee_hash: ShortHash,
    pub(crate) nonce: u64,
    pub(crate) hash: Option<Hash>,
    pub(crate) signature: Option<Signature>,
}

impl Burn {
    pub const TX_TYPE: u8 = 7;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<DbHasher, Codec>) -> bool {
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

        let burner_signing_addr = NormalAddress::from_pkey(&self.burner);

        // Do not allow address re-usage
        if self.next_address == burner_signing_addr {
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
        let addr_mapping_key = [burner_signing_addr.as_bytes(), &b".am"[..]].concat();

        // Retrieve burner account permanent address
        let permanent_addr = match trie.get(&addr_mapping_key) {
            Ok(Some(perm_addr)) => NormalAddress::from_bytes(&perm_addr).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        // Do not allow address re-usage
        if self.next_address == permanent_addr {
            return false;
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

            // Subtract fee from burner
            fee_balance -= self.fee.clone();

            // Subtract amount transferred from burner
            cur_balance -= self.amount.clone();

            cur_balance >= zero && fee_balance >= zero
        }
    }

    /// Applies the burn transaction to the provided database.
    ///
    /// This function will panic if the `burner` account does not exist.
    pub fn apply(&self, trie: &mut TrieDBMut<DbHasher, Codec>) {
        let bin_burner = &self.burner.0;
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;
        let sender_signing_addr = NormalAddress::from_pkey(&self.burner);

        // Calculate address mapping key
        //
        // An address mapping is a mapping between
        // the account's signing address and an
        // account's receiving address.
        //
        // They key of the address mapping has the following format:
        // `<signing-address>.am`
        let burner_addr_mapping_key = [sender_signing_addr.as_bytes(), &b".am"[..]].concat();
        let next_addr_mapping_key = [self.next_address.as_bytes(), &b".am"[..]].concat();

        // Retrieve sender account permanent address
        let burner_perm_addr = trie.get(&burner_addr_mapping_key).unwrap().unwrap();
        let burner_perm_addr = NormalAddress::from_bytes(&burner_perm_addr).unwrap();

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let nonce_key = [burner_perm_addr.as_bytes(), &b".n"[..]].concat();

        // Retrieve serialized nonce
        let bin_nonce = &trie.get(&nonce_key).unwrap().unwrap();

        let mut nonce_rdr = Cursor::new(bin_nonce);

        // Read the nonce of the burner
        let mut nonce = nonce_rdr.read_u64::<BigEndian>().unwrap();

        // Increment burner nonce
        nonce += 1;

        let mut nonce_buf: Vec<u8> = Vec::with_capacity(8);

        // Write new nonce to buffer
        nonce_buf.write_u64::<BigEndian>(nonce).unwrap();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let cur_key = &[burner_perm_addr.as_bytes(), &b"."[..], &bin_asset_hash[..]].concat();
        let fee_key = &[burner_perm_addr.as_bytes(), &b"."[..], &bin_fee_hash[..]].concat();

        if bin_fee_hash == bin_asset_hash {
            // The transaction's fee is paid in the same currency
            // that is being burned, so we only retrieve one balance.
            let mut balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&cur_key).unwrap(),
                    "The burner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from balance
            balance -= self.fee.clone();

            // Subtract amount transferred from balance
            balance -= self.amount.clone();

            // Update trie
            trie.insert(&cur_key, &balance.to_bytes()).unwrap();
            trie.insert(&nonce_key, &nonce_buf).unwrap();

            // Update burner address mapping
            trie.remove(&burner_addr_mapping_key).unwrap();
            trie.insert(&next_addr_mapping_key, burner_perm_addr.as_bytes())
                .unwrap();
        } else {
            // The transaction's fee is paid in a different currency
            // than the one being transferred so we retrieve both balances.
            let mut cur_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&cur_key).unwrap(),
                    "The burner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            let mut fee_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&fee_key).unwrap(),
                    "The burner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from burner
            fee_balance -= self.fee.clone();

            // Subtract amount transferred from burner
            cur_balance -= self.amount.clone();

            // Update trie
            trie.insert(&cur_key, &cur_balance.to_bytes()).unwrap();
            trie.insert(&fee_key, &fee_balance.to_bytes()).unwrap();
            trie.insert(&nonce_key, &nonce_buf).unwrap();

            // Update burner address mapping
            trie.remove(&burner_addr_mapping_key).unwrap();
            trie.insert(&next_addr_mapping_key, burner_perm_addr.as_bytes())
                .unwrap();
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
            Some(ref sig) => crypto::verify(&message, sig, &self.burner),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type     - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Amount length        - 8bits
    /// 4) Nonce                - 64bits
    /// 5) Currency flag        - 1byte (Value is 1 if currency and fee hashes are identical. Otherwise is 0)
    /// 6) Currency hash        - 8byte binary
    /// 7) Fee hash             - 8byte binary (Non-existent if currency flag is true)
    /// 8) Burner               - 33byte binary
    /// 9) Next address         - 33byte binary
    /// 10) Signature           - 64byte binary
    /// 11) Amount              - Binary of amount length
    /// 12) Fee                 - Binary of fee length
    /// 13) Signature           - Binary of signature length
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

        let next_address = self.next_address.to_bytes();
        let asset_hash = &self.asset_hash.0;
        let fee_hash = &self.fee_hash.0;
        let currency_flag = if asset_hash == fee_hash { 1 } else { 0 };

        let amount = self.amount.to_bytes();
        let fee = self.fee.to_bytes();

        let amount_len = amount.len();
        let fee_len = fee.len();
        let signature_len = signature.len();
        let nonce = &self.nonce;

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();
        buffer.write_u8(currency_flag).unwrap();
        buffer.extend_from_slice(asset_hash);

        if currency_flag == 0 {
            buffer.extend_from_slice(fee_hash);
        }

        buffer.extend_from_slice(&self.burner.0);
        buffer.extend_from_slice(&next_address);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(&amount);
        buffer.extend_from_slice(&fee);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Burn, &'static str> {
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

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        rdr.set_position(11);

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
        let _: Vec<u8> = buf.drain(..12).collect();

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

        let burner = if buf.len() > 32 as usize {
            let burner_vec: Vec<u8> = buf.drain(..32).collect();
            let mut burner = [0; 32];
            burner.copy_from_slice(&burner_vec);

            Pk(burner)
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

        let mut burn = Burn {
            burner,
            next_address,
            fee_hash,
            fee,
            amount,
            asset_hash,
            nonce,
            hash: None,
            signature: Some(signature),
        };

        burn.compute_hash();
        Ok(burn)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &TrieDBMut<DbHasher, Codec>, sk: Sk) -> Burn {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &Burn) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let next_address = obj.next_address.to_bytes();
    let amount = obj.amount.to_bytes();
    let fee = obj.fee.to_bytes();
    let asset_hash = &obj.asset_hash.0;
    let fee_hash = &obj.fee_hash.0;

    buf.write_u64::<BigEndian>(obj.nonce).unwrap();
    buf.extend_from_slice(&obj.burner.0);
    buf.extend_from_slice(&next_address);
    buf.extend_from_slice(asset_hash);
    buf.extend_from_slice(fee_hash);
    buf.extend_from_slice(&amount);
    buf.extend_from_slice(&fee);
    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Burn {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Burn {
        let (pk, _) = crypto::gen_keypair();
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);

        let asset_hash = Arbitrary::arbitrary(g);
        let fee_hash = if random == 1 {
            asset_hash
        } else {
            Arbitrary::arbitrary(g)
        };

        let mut tx = Burn {
            burner: pk,
            next_address: Arbitrary::arbitrary(g),
            fee_hash,
            fee: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            asset_hash,
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
    use account::{Address, NormalAddress};
    use crypto::Identity;

    #[test]
    fn validate() {
        let id = Identity::new();
        let id2 = Identity::new();
        let burner_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize burner balance
            test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: id.pkey().clone(),
            next_address,
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash,
            fee_hash: asset_hash,
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
    fn validate_no_funds() {
        let id = Identity::new();
        let id2 = Identity::new();
        let burner_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize burner balance
            test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: id.pkey().clone(),
            next_address,
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash,
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
    fn validate_different_currencies() {
        let id = Identity::new();
        let id2 = Identity::new();
        let burner_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize burner balance
            test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0");
            test_helpers::init_balance(&mut trie, burner_addr.clone(), fee_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: id.pkey().clone(),
            next_address,
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash,
            fee_hash: asset_hash,
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
    fn validate_no_funds_different_currencies() {
        let id = Identity::new();
        let id2 = Identity::new();
        let burner_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize burner balance
            test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10.0");
            test_helpers::init_balance(&mut trie, burner_addr.clone(), fee_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: id.pkey().clone(),
            next_address,
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash,
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
    fn validate_no_funds_for_fee_different_currencies() {
        let id = Identity::new();
        let id2 = Identity::new();
        let burner_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1").to_short();
        let fee_hash = crypto::hash_slice(b"Test currency 2").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize burner balance
            test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10.0");
            test_helpers::init_balance(&mut trie, burner_addr.clone(), fee_hash, b"10.0");
        }

        let amount = Balance::from_bytes(b"5.0").unwrap();
        let fee = Balance::from_bytes(b"20.0").unwrap();

        let mut tx = Burn {
            burner: id.pkey().clone(),
            next_address,
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash,
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
    fn validate_zero() {
        let id = Identity::new();
        let id2 = Identity::new();
        let burner_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize burner balance
            test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0")
        };

        let amount = Balance::zero();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: id.pkey().clone(),
            next_address,
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash,
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
    fn apply_it_burns_coins() {
        let id = Identity::new();
        let id2 = Identity::new();
        let burner_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();
        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;

        {
            let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

            // Manually initialize burner balance
            test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0");

            let mut tx = Burn {
                burner: id.pkey().clone(),
                next_address,
                amount: amount.clone(),
                fee: fee.clone(),
                asset_hash,
                fee_hash: asset_hash,
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

        let burner_nonce_key = [burner_addr.as_bytes(), &b".n"[..]].concat();
        let bin_burner_nonce = &trie.get(&burner_nonce_key).unwrap().unwrap();

        let bin_asset_hash = &asset_hash.0;

        let burner_balance_key = [burner_addr.as_bytes(), &b"."[..], bin_asset_hash].concat();

        let balance =
            Balance::from_bytes(&trie.get(&burner_balance_key).unwrap().unwrap()).unwrap();

        // Check nonces
        assert_eq!(bin_burner_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);

        // Verify that the correct amount of funds have been subtracted from the sender
        assert_eq!(
            balance,
            Balance::from_bytes(b"10000.0").unwrap() - amount.clone() - fee.clone()
        );
    }

    quickcheck! {
        fn serialize_deserialize(tx: Burn) -> bool {
            tx == Burn::from_bytes(&Burn::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: Burn) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(id: Identity, next_address: NormalAddress, amount: Balance, fee: Balance, asset_hash: ShortHash, fee_hash: ShortHash) -> bool {
            let mut tx = Burn {
                burner: id.pkey().clone(),
                next_address,
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
