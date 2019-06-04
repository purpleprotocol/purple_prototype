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

use account::{Address, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Signature, Hash};
use crypto::{PublicKey as Pk, SecretKey as Sk};
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use std::io::Cursor;
use std::str;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Burn {
    burner: Address,
    amount: Balance,
    fee: Balance,
    asset_hash: Hash,
    fee_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl Burn {
    pub const TX_TYPE: u8 = 7;

    /// Validates the transaction against the provided state.
    pub fn validate(&mut self, trie: &TrieDBMut<BlakeDbHasher, Codec>) -> bool {
        let zero = Balance::from_bytes(b"0.0").unwrap();
        let burner = &self.burner.clone();
        let signature = &self.signature.clone();

        // You cannot burn 0 coins
        if self.amount == zero {
            return false;
        }

        if !self.validate_signature(burner, signature, trie) {
            return false;
        }

        let bin_burner = &self.burner.to_bytes();
        let bin_asset_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();

        // Convert address to strings
        let burner = hex::encode(bin_burner);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let nonce_key = format!("{}.n", burner);
        let nonce_key = nonce_key.as_bytes();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let cur_key = format!("{}.{}", burner, asset_hash);
        let fee_key = format!("{}.{}", burner, fee_hash);

        // Retrieve serialized nonce
        let bin_nonce = match trie.get(&nonce_key) {
            Ok(Some(nonce)) => nonce,
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        if fee_hash == asset_hash {
            // The transaction's fee is paid in the same currency
            // that is being burned, so we only retrieve one balance.
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
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_burner = &self.burner.to_bytes();
        let bin_asset_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();

        // Convert address to strings
        let burner = hex::encode(bin_burner);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let nonce_key = format!("{}.n", burner);
        let nonce_key = nonce_key.as_bytes();

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
        let cur_key = format!("{}.{}", burner, asset_hash);
        let fee_key = format!("{}.{}", burner, fee_hash);

        if fee_hash == asset_hash {
            // The transaction's fee is paid in the same currency
            // that is being burned, so we only retrieve one balance.
            let mut balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&cur_key.as_bytes()).unwrap(),
                    "The burner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from balance
            balance -= self.fee.clone();

            // Subtract amount transferred from balance
            balance -= self.amount.clone();

            // Update trie
            trie.insert(cur_key.as_bytes(), &balance.to_bytes())
                .unwrap();
            trie.insert(nonce_key, &nonce_buf).unwrap();
        } else {
            // The transaction's fee is paid in a different currency
            // than the one being transferred so we retrieve both balances.
            let mut cur_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&cur_key.as_bytes()).unwrap(),
                    "The burner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            let mut fee_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&fee_key.as_bytes()).unwrap(),
                    "The burner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from burner
            fee_balance -= self.fee.clone();

            // Subtract amount transferred from burner
            cur_balance -= self.amount.clone();

            // Update trie
            trie.insert(cur_key.as_bytes(), &cur_balance.to_bytes())
                .unwrap();
            trie.insert(fee_key.as_bytes(), &fee_balance.to_bytes())
                .unwrap();
            trie.insert(nonce_key, &nonce_buf).unwrap();
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
        let signature = crypto::sign(&message, &skey);
        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => {
                crypto::verify(&message, sig, &addr.pkey())
            }
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type     - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Amount length        - 8bits
    /// 4) Signature length     - 16bits
    /// 5) Burner               - 33byte binary
    /// 6) Currency hash        - 32byte binary
    /// 7) Fee hash             - 32byte binary
    /// 8) Hash                 - 32byte binary
    /// 9) Amount               - Binary of amount length
    /// 10) Fee                 - Binary of fee length
    /// 11) Signature           - Binary of signature length
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

        let burner = &self.burner.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();

        let amount_len = amount.len();
        let fee_len = fee.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();

        buffer.append(&mut burner.to_vec());
        buffer.append(&mut asset_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut signature);

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

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..5).collect();

        let burner = if buf.len() > 33 as usize {
            let burner_vec: Vec<u8> = buf.drain(..33).collect();

            match Address::from_bytes(&burner_vec) {
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

        let amount = if buf.len() > amount_len as usize {
            let amount_vec: Vec<u8> = buf.drain(..amount_len as usize).collect();

            match Balance::from_bytes(&amount_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad amount"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let fee = if buf.len() > fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad gas price"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() == signature_len as usize {
            let sig_vec: Vec<u8> = buf.drain(..signature_len as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_) => return Err("Bad signature"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let burn = Burn {
            burner: burner,
            fee_hash: fee_hash,
            fee: fee,
            amount: amount,
            asset_hash: asset_hash,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(burn)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Burn {
        unimplemented!();
    }

    impl_hash!();
    impl_validate_signature!();
}

fn assemble_hash_message(obj: &Burn) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut burner = obj.burner.to_bytes();
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to hash
    buf.append(&mut burner);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &Burn) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut burner = obj.burner.to_bytes();
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to sign
    buf.append(&mut burner);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Burn {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Burn {
        Burn {
            burner: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
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
        let id = Identity::new();
        let burner_addr = Address::normal_from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize burner balance
        test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: burner_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.hash();

        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds() {
        let id = Identity::new();
        let burner_addr = Address::normal_from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize burner balance
        test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: burner_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_different_currencies() {
        let id = Identity::new();
        let burner_addr = Address::normal_from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize burner balance
        test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0");
        test_helpers::init_balance(&mut trie, burner_addr.clone(), fee_hash, b"10.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: burner_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.hash();

        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds_different_currencies() {
        let id = Identity::new();
        let burner_addr = Address::normal_from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize burner balance
        test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10.0");
        test_helpers::init_balance(&mut trie, burner_addr.clone(), fee_hash, b"10.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: burner_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_no_funds_for_fee_different_currencies() {
        let id = Identity::new();
        let burner_addr = Address::normal_from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency 1");
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize burner balance
        test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10.0");
        test_helpers::init_balance(&mut trie, burner_addr.clone(), fee_hash, b"10.0");

        let amount = Balance::from_bytes(b"5.0").unwrap();
        let fee = Balance::from_bytes(b"20.0").unwrap();

        let mut tx = Burn {
            burner: burner_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_zero() {
        let id = Identity::new();
        let burner_addr = Address::normal_from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize burner balance
        test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0");

        let amount = Balance::from_bytes(b"0.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: burner_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_burns_coins() {
        let id = Identity::new();
        let burner_addr = Address::normal_from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize burner balance
        test_helpers::init_balance(&mut trie, burner_addr.clone(), asset_hash, b"10000.0");

        let amount = Balance::from_bytes(b"100.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();

        let mut tx = Burn {
            burner: burner_addr.clone(),
            amount: amount.clone(),
            fee: fee.clone(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id.skey().clone());
        tx.hash();

        // Apply transaction
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let burner_nonce_key = format!("{}.n", hex::encode(&burner_addr.to_bytes()));
        let burner_nonce_key = burner_nonce_key.as_bytes();

        let bin_burner_nonce = &trie.get(&burner_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let hex_asset_hash = hex::encode(&bin_asset_hash);

        let burner_balance_key = format!(
            "{}.{}",
            hex::encode(&burner_addr.to_bytes()),
            hex_asset_hash
        );
        let burner_balance_key = burner_balance_key.as_bytes();

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
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(id: Identity, amount: Balance, fee: Balance, asset_hash: Hash, fee_hash: Hash) -> bool {
            let mut tx = Burn {
                burner: Address::normal_from_pkey(*id.pkey()),
                amount: amount,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
