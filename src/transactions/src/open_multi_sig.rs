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

use account::{NormalAddress, MultiSigAddress, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Signature, Hash, SecretKey as Sk};
use std::io::Cursor;
use patricia_trie::{TrieMut, TrieDBMut};
use persistence::{BlakeDbHasher, Codec};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OpenMultiSig {
    creator: NormalAddress,
    keys: Vec<NormalAddress>,
    required_keys: u8,
    amount: Balance,
    currency_hash: Hash,
    fee: Balance,
    fee_hash: Hash,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<MultiSigAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenMultiSig {
    pub const TX_TYPE: u8 = 5;

    /// Applies the open shares transaction to the provided database.
    ///
    /// This function will panic if the `creator` account does not exist
    /// or if the account address already exists in the ledger.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_creator = &self.creator.to_bytes();
        let bin_address = &self.address.clone().unwrap().to_bytes();
        let bin_currency_hash = &self.currency_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();
        let required_keys = &self.required_keys;
        let keys: Vec<Vec<u8>> = self.keys
            .iter()
            .map(|k| k.to_bytes())
            .collect();

        let bin_keys: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&keys);

        // Convert addresses to strings
        let creator = hex::encode(bin_creator);
        let address = hex::encode(bin_address);

        // Convert hashes to strings
        let cur_hash = hex::encode(bin_currency_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate nonce keys
        // 
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let creator_nonce_key = format!("{}.n", creator);
        let address_nonce_key = format!("{}.n", address);
        let creator_nonce_key = creator_nonce_key.as_bytes();
        let address_nonce_key = address_nonce_key.as_bytes();

        if let Ok(Some(_)) = trie.get(&address_nonce_key) {
            panic!("The created address already exists in the ledger!");
        }

        // Calculate `required keys` key
        //
        // The key of the `required keys` entry has the following format:
        // `<account-address>.r`
        let required_ks_key = format!("{}.r", address);
        let required_ks_key = required_ks_key.as_bytes(); 

        // Calculate `keys` key
        //
        // The key of the `keys` entry has the following format:
        // `<account-address>.k`
        let ks_key = format!("{}.k", address);
        let ks_key = ks_key.as_bytes();

        // Retrieve serialized nonce
        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();

        let mut nonce_rdr = Cursor::new(bin_creator_nonce);

        // Read the nonce of the creator
        let mut nonce = nonce_rdr.read_u64::<BigEndian>().unwrap();

        // Increment creator nonce
        nonce += 1;

        let mut nonce_buf: Vec<u8> = Vec::with_capacity(8);

        // Write new nonce to buffer
        nonce_buf.write_u64::<BigEndian>(nonce).unwrap();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let creator_cur_key = format!("{}.{}", creator, cur_hash);
        let creator_fee_key = format!("{}.{}", creator, fee_hash);
        let address_cur_key = format!("{}.{}", address, cur_hash);

        if fee_hash == cur_hash {
            // The transaction's fee is paid in the same currency
            // that is being transferred, so we only retrieve one
            // balance.
            let mut creator_balance = unwrap!(
                Balance::from_bytes(
                    &unwrap!(
                        trie.get(&creator_cur_key.as_bytes()).unwrap(),
                        "The creator does not have an entry for the given currency"
                    )
                ),
                "Invalid stored balance format"
            );

            // Subtract fee from creator balance
            creator_balance -= self.fee.clone();

            // Subtract amount transferred from creator balance
            creator_balance -= self.amount.clone();

            let receiver_balance = self.amount.clone();

            // Update trie
            trie.insert(ks_key, &bin_keys).unwrap();
            trie.insert(required_ks_key, &vec![*required_keys]).unwrap();
            trie.insert(creator_cur_key.as_bytes(), &creator_balance.to_bytes()).unwrap();
            trie.insert(address_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
            trie.insert(creator_nonce_key, &nonce_buf).unwrap();
            trie.insert(address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        } else {
            // The transaction's fee is paid in a different currency
            // than the one being transferred so we retrieve both balances.
            let mut creator_cur_balance = unwrap!(
                Balance::from_bytes(
                    &unwrap!(
                        trie.get(&creator_cur_key.as_bytes()).unwrap(),
                        "The creator does not have an entry for the given currency"
                    )
                ),
                "Invalid stored balance format"
            );

            let mut creator_fee_balance = unwrap!(
                Balance::from_bytes(
                    &unwrap!(
                        trie.get(&creator_fee_key.as_bytes()).unwrap(),
                        "The creator does not have an entry for the given currency"
                    )
                ),
                "Invalid stored balance format"
            );

            // Subtract fee from creator
            creator_fee_balance -= self.fee.clone();

            // Subtract amount transferred from creator
            creator_cur_balance -= self.amount.clone();

            let receiver_balance = self.amount.clone();

            // Update trie
            trie.insert(ks_key, &bin_keys).unwrap();
            trie.insert(required_ks_key, &vec![*required_keys]).unwrap();
            trie.insert(creator_cur_key.as_bytes(), &creator_cur_balance.to_bytes()).unwrap();
            trie.insert(creator_fee_key.as_bytes(), &creator_fee_balance.to_bytes()).unwrap();
            trie.insert(address_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
            trie.insert(creator_nonce_key, &nonce_buf).unwrap();
            trie.insert(address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        }
    }

    pub fn compute_address(&mut self) {
        let addr = MultiSigAddress::compute(&self.keys, self.creator.clone(), self.nonce);
        self.address = Some(addr);
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

        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => { 
                crypto::verify(&message, sig.clone(), self.creator.pkey())
            },
            None => {
                false
            }
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(5)      - 8bits
    /// 2) Required keys            - 8bits
    /// 3) Amount length            - 8bits
    /// 4) Fee length               - 8bits
    /// 5) Keys length              - 16bits
    /// 6) Nonce                    - 64bits
    /// 7) Fee hash                 - 32byte binary
    /// 8) Currency hash            - 32byte binary
    /// 9) Creator                  - 33byte binary
    /// 10) Address                 - 33byte binary
    /// 11) Hash                    - 32bytse binary
    /// 12) Signature               - 64byte binary
    /// 13) Amount                  - Binary of amount length
    /// 14) Fee                     - Binary of fee length
    /// 15) Keys                    - Binary of keys length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let address = if let Some(address) = &self.address {
            address.to_bytes()
        } else {
            return Err("Address field is missing");
        };

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

        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(self.keys.len());
        
        for k in self.keys.iter() {
            keys.push(k.to_bytes());
        }

        // Encode keys
        let mut keys: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&keys);

        let creator = &self.creator.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let currency_hash = &&self.currency_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();
        let nonce = &self.nonce;
        let required_keys = &self.required_keys;

        let fee_len = fee.len();
        let amount_len = amount.len();
        let keys_len = keys.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(*required_keys).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(keys_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut creator.to_vec());
        buffer.append(&mut address.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut keys);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<OpenMultiSig, &'static str> {
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

        let required_keys = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad required keys");
        };

        rdr.set_position(2);

        let amount_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad amount len");
        };

        rdr.set_position(3);

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(4);

        let keys_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad keys len");
        };

        rdr.set_position(6);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..14).collect();

        let fee_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
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

        let creator = if buf.len() > 33 as usize {
            let creator_vec: Vec<u8> = buf.drain(..33).collect();
            
            match NormalAddress::from_bytes(&creator_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let address = if buf.len() > 33 as usize {
            let address_vec: Vec<u8> = buf.drain(..33).collect();
            
            match MultiSigAddress::from_bytes(&address_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
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

        let signature = if buf.len() > 65 as usize {
            let sig_vec: Vec<u8> = buf.drain(..65 as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig)   => sig,
                Err(err)  => return Err(err)
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

        let fee = if buf.len() > fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad fee")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let keys = if buf.len() == keys_len as usize {
            let keys_vec: Vec<u8> = buf.drain(..keys_len as usize).collect();
            let deserialized_keys: Vec<Vec<u8>> = rlp::decode_list(&keys_vec);
            let mut keys: Vec<NormalAddress> = Vec::with_capacity(keys_len as usize);

            for k in deserialized_keys {
                match NormalAddress::from_bytes(&k) {
                    Ok(addr) => keys.push(addr),
                    Err(err) => return Err(err)
                }
            }

            keys
        } else {
            return Err("Incorrect packet structure")
        };

        let open_multi_sig = OpenMultiSig {
            creator: creator,
            required_keys: required_keys,
            keys: keys,
            currency_hash: currency_hash,
            amount: amount,
            fee_hash: fee_hash,
            fee: fee,
            nonce: nonce,
            address: Some(address),
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(open_multi_sig)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &OpenMultiSig) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut address = if let Some(ref address) = obj.address {
        address.to_bytes()
    } else {
        panic!("Address field is missing");
    };

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(obj.keys.len());
        
    for k in obj.keys.iter() {
        keys.push(k.to_bytes());
    }

    // Encode keys
    let mut keys: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&keys);

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let currency_hash = &obj.currency_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let nonce = obj.nonce;
    let required_keys = obj.required_keys;

    buf.write_u8(required_keys).unwrap();
    buf.write_u64::<BigEndian>(nonce).unwrap();

    // Compose data to hash
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut creator);
    buf.append(&mut address);
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut keys);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &OpenMultiSig) -> Vec<u8> {
    let mut address = if let Some(ref address) = obj.address {
        address.to_bytes()
    } else {
        panic!("Address field is missing");
    };

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(obj.keys.len());
        
    for k in obj.keys.iter() {
        keys.push(k.to_bytes());
    }

    // Encode keys
    let mut keys: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&keys);

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let currency_hash = &obj.currency_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let nonce = obj.nonce;
    let required_keys = obj.required_keys;

    buf.write_u8(required_keys).unwrap();
    buf.write_u64::<BigEndian>(nonce).unwrap();

    // Compose data to hash
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut creator);
    buf.append(&mut address);
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut keys);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenMultiSig {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> OpenMultiSig {
        OpenMultiSig {
            creator: Arbitrary::arbitrary(g),
            keys: Arbitrary::arbitrary(g),
            required_keys: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            address: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test_helpers;
    
    use super::*;
    use account::Address;
    use crypto::Identity;

    #[test]
    fn apply_it_correctly_creates_a_shares_account() {
        let id = Identity::new();
        let creator_addr = NormalAddress::from_pkey(*id.pkey());
        let cur_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, Address::Normal(creator_addr.clone()), cur_hash, b"10000.0");

        let amount = Balance::from_bytes(b"30.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();
        let keys: Vec<NormalAddress> = (0..10)
            .into_iter()
            .map(|_| {
                let id = Identity::new();
                NormalAddress::from_pkey(*id.pkey())
            })
            .collect();

        let required_keys = 6;

        let mut tx = OpenMultiSig {
            creator: creator_addr.clone(),
            fee: fee.clone(),
            keys: keys.clone(),
            required_keys: required_keys.clone(),
            fee_hash: cur_hash,
            amount: amount.clone(),
            currency_hash: cur_hash,
            nonce: 3429,
            address: None,
            signature: None,
            hash: None
        };

        tx.compute_address();
        tx.sign(id.skey().clone());
        tx.hash();

        // Apply transaction
        tx.apply(&mut trie);
        
        // Commit changes
        trie.commit();
        
        let creator_nonce_key = format!("{}.n", hex::encode(&creator_addr.to_bytes()));
        let creator_nonce_key = creator_nonce_key.as_bytes();
        let receiver_nonce_key = format!("{}.n", hex::encode(tx.address.clone().unwrap().to_bytes()));
        let receiver_nonce_key = receiver_nonce_key.as_bytes();

        let required_ks_key = format!("{}.r", hex::encode(tx.address.clone().unwrap().to_bytes()));
        let required_ks_key = required_ks_key.as_bytes();
        let ks_key = format!("{}.k", hex::encode(tx.address.unwrap().to_bytes()));
        let ks_key = ks_key.as_bytes();

        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();
        let bin_receiver_nonce = &trie.get(&receiver_nonce_key).unwrap().unwrap();

        let bin_cur_hash = cur_hash.to_vec();
        let hex_cur_hash = hex::encode(&bin_cur_hash);

        let creator_balance_key = format!("{}.{}", hex::encode(&creator_addr.to_bytes()), hex_cur_hash);
        let creator_balance_key = creator_balance_key.as_bytes();

        let balance = Balance::from_bytes(&trie.get(&creator_balance_key).unwrap().unwrap()).unwrap();
        let decoded_keys: Vec<Vec<u8>> = rlp::decode_list(&trie.get(&ks_key).unwrap().unwrap());
        let written_keys: Vec<NormalAddress> = decoded_keys
            .iter()
            .map(|k| NormalAddress::from_bytes(k).unwrap())
            .collect();
        
        let written_required_keys = trie.get(&required_ks_key).unwrap().unwrap().pop().unwrap();

        // Check nonces
        assert_eq!(bin_creator_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bin_receiver_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 0]);

        // Verify that the correct amount of funds have been subtracted from the sender
        assert_eq!(balance, Balance::from_bytes(b"10000.0").unwrap() - amount.clone() - fee.clone());

        // Verify shares and share map
        assert_eq!(written_keys, keys);
        assert_eq!(written_required_keys, required_keys);
    }

    quickcheck! {
        fn serialize_deserialize(tx: OpenMultiSig) -> bool {
            tx == OpenMultiSig::from_bytes(&OpenMultiSig::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: OpenMultiSig) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            keys: Vec<NormalAddress>,
            required_keys: u8,
            amount: Balance,
            currency_hash: Hash,
            fee: Balance,
            fee_hash: Hash,
            address: MultiSigAddress,
            nonce: u64
        ) -> bool {
            let id = Identity::new();

            let mut tx = OpenMultiSig {
                creator: NormalAddress::from_pkey(*id.pkey()),
                keys: keys,
                required_keys: required_keys,
                amount: amount,
                currency_hash: currency_hash,
                fee: fee,
                fee_hash: fee_hash,
                nonce: nonce,
                address: Some(address),
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}