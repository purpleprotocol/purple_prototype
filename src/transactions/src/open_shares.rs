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

use account::{NormalAddress, ShareholdersAddress, Balance, Shares, ShareMap};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, Signature, SecretKey as Sk};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use patricia_trie::{TrieMut, TrieDBMut, NodeCodec};
use elastic_array::ElasticArray128;
use persistence::{BlakeDbHasher, Codec};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OpenShares {
    creator: NormalAddress,
    shares: Shares,
    share_map: ShareMap,
    amount: Balance,
    currency_hash: Hash,
    fee: Balance,
    fee_hash: Hash,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<ShareholdersAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stock_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenShares {
    pub const TX_TYPE: u8 = 6;

    /// Applies the open shares transaction to the provided database.
    ///
    /// This function will panic if the `creator` account does not exist
    /// or if the account address already exists in the ledger.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_creator = &self.creator.to_bytes();
        let bin_address = &self.address.clone().unwrap().to_bytes();
        let bin_currency_hash = &self.currency_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();
        let bin_stock_hash = &self.stock_hash.unwrap().to_vec();

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

        // Calculate shares and share map keys
        //
        // The keys of shares objects have the following format:
        // `<account-address>.s`
        //
        // The keys of share map objects have the following format:
        // `<account-address>.sm`
        let shares_key = format!("{}.s", address);
        let share_map_key = format!("{}.sm", address);
        let shares_key = shares_key.as_bytes();
        let share_map_key = share_map_key.as_bytes();

        // Calculate stock hash key
        //
        // The key of a shareholders account's stock hash has the following format:
        // `<account-address>.sh`
        let stock_hash_key = format!("{}.sh", address);

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

            allocate_shares(trie, &self.stock_hash.unwrap(), &self.share_map);

            // Update trie
            trie.insert(creator_cur_key.as_bytes(), &creator_balance.to_bytes()).unwrap();
            trie.insert(address_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
            trie.insert(creator_nonce_key, &nonce_buf).unwrap();
            trie.insert(address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            trie.insert(shares_key, &self.shares.to_bytes()).unwrap();
            trie.insert(share_map_key, &self.share_map.to_bytes()).unwrap();
            trie.insert(stock_hash_key.as_bytes(), bin_stock_hash).unwrap();
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

            allocate_shares(trie, &self.stock_hash.unwrap(), &self.share_map);

            // Update trie
            trie.insert(creator_cur_key.as_bytes(), &creator_cur_balance.to_bytes()).unwrap();
            trie.insert(creator_fee_key.as_bytes(), &creator_fee_balance.to_bytes()).unwrap();
            trie.insert(address_cur_key.as_bytes(), &receiver_balance.to_bytes()).unwrap();
            trie.insert(creator_nonce_key, &nonce_buf).unwrap();
            trie.insert(address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            trie.insert(shares_key, &self.shares.to_bytes()).unwrap();
            trie.insert(share_map_key, &self.share_map.to_bytes()).unwrap();
            trie.insert(stock_hash_key.as_bytes(), bin_stock_hash).unwrap();
        }
    }

    pub fn compute_address(&mut self) {
        let addr = ShareholdersAddress::compute(&self.share_map.keys(), self.creator.clone(), self.nonce);
        self.address = Some(addr);
    }

    pub fn compute_stock_hash(&mut self) {
        let mut buf: Vec<u8> = vec![];
        let keys: Vec<Vec<u8>> = self.share_map
            .keys()
            .iter()
            .map(|k| k.to_bytes())
            .collect();

        let mut encoded_list = rlp::encode_list::<Vec<u8>, _>(&keys);

        // Write nonce to buf
        buf.write_u64::<BigEndian>(self.nonce).unwrap();

        // Write keys to buf
        buf.append(&mut encoded_list);

        let stock_hash = crypto::hash_slice(&buf);

        // Add stock hash to tx
        self.stock_hash = Some(stock_hash);
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
    /// 1) Transaction type(6)      - 8bits
    /// 2) Amount length            - 8bits
    /// 3) Fee length               - 8bits
    /// 4) Shares length            - 16bits
    /// 5) Share map length         - 16bits
    /// 6) Nonce                    - 64bits
    /// 7) Stock hash               - 32byte binary
    /// 8) Fee hash                 - 32byte binary
    /// 9) Currency hash            - 32byte binary
    /// 10) Creator                 - 33byte binary
    /// 11) Address                 - 33byte binary
    /// 12) Hash                    - 32byte binary
    /// 13) Signature               - 64byte binary
    /// 14) Amount                  - Binary of amount length
    /// 15) Fee                     - Binary of fee length
    /// 16) Shares                  - Binary of shares length
    /// 17) Share map               - Binary of share map length
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

        let stock_hash = if let Some(stock_hash) = &self.stock_hash {
            &stock_hash.0
        } else {
            return Err("Stock hash field is missing");
        };

        let signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let creator = &self.creator.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let currency_hash = &&self.currency_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();
        let shares = &self.shares.to_bytes();
        let share_map = &self.share_map.to_bytes();
        let nonce = &self.nonce;

        let fee_len = fee.len();
        let amount_len = amount.len();
        let shares_len = shares.len();
        let share_map_len = share_map.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(shares_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(share_map_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.append(&mut stock_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut creator.to_vec());
        buffer.append(&mut address.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut shares.to_vec());
        buffer.append(&mut share_map.to_vec());

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<OpenShares, &'static str> {
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

        let shares_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad shares len");
        };

        rdr.set_position(5);

        let share_map_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad share map len");
        };

        rdr.set_position(7);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..15).collect();

        let stock_hash = if buf.len() > 32 as usize {
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
            
            match ShareholdersAddress::from_bytes(&address_vec) {
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

        let shares = if buf.len() > shares_len as usize {
            let shares_vec: Vec<u8> = buf.drain(..shares_len as usize).collect();

            match Shares::from_bytes(&shares_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad shares")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let share_map = if buf.len() == share_map_len as usize {
            let share_map_vec: Vec<u8> = buf.drain(..share_map_len as usize).collect();

            match ShareMap::from_bytes(&share_map_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad share map")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let open_shares = OpenShares {
            creator: creator,
            shares: shares,
            share_map: share_map,
            currency_hash: currency_hash,
            amount: amount,
            fee_hash: fee_hash,
            fee: fee,
            nonce: nonce,
            stock_hash: Some(stock_hash),
            address: Some(address),
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(open_shares)
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &OpenShares) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut address = if let Some(ref address) = obj.address {
        address.to_bytes()
    } else {
        panic!("Address field is missing!");
    };

    let stock_hash = if let Some(ref stock_hash) = obj.stock_hash {
        stock_hash.0
    } else {
        panic!("Stock hash field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let currency_hash = &obj.currency_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let nonce = obj.nonce;
    let mut shares = obj.shares.to_bytes();
    let mut share_map = obj.share_map.to_bytes();

    buf.write_u64::<BigEndian>(nonce).unwrap();

    // Compose data to hash
    buf.append(&mut stock_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut creator);
    buf.append(&mut address);
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut signature);
    buf.append(&mut shares);
    buf.append(&mut share_map);

    buf
}

fn assemble_sign_message(obj: &OpenShares) -> Vec<u8> {
    let mut address = if let Some(ref address) = obj.address {
        address.to_bytes()
    } else {
        panic!("Address field is missing!");
    };

    let stock_hash = if let Some(ref stock_hash) = obj.stock_hash {
        stock_hash.0
    } else {
        panic!("Stock hash field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let currency_hash = &obj.currency_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let nonce = obj.nonce;
    let mut shares = obj.shares.to_bytes();
    let mut share_map = obj.share_map.to_bytes();

    buf.write_u64::<BigEndian>(nonce).unwrap();

    // Compose data to hash
    buf.append(&mut stock_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut creator);
    buf.append(&mut address);
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut shares);
    buf.append(&mut share_map);

    buf
}

// Writes the shares in the given share map to each shareholder.
//
// If a listed shareholder's account is not created, this will also create it.
fn allocate_shares(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, stock_hash: &Hash, share_map: &ShareMap) {
    for shareholder in share_map.keys() {
        let stock_hash = stock_hash.to_vec();
        let stock_hash = hex::encode(stock_hash);
        let shares = share_map.get(shareholder.clone()).unwrap();
        let str_shares = format!("{}.0", shares);
        let shares = Balance::from_bytes(str_shares.as_bytes()).unwrap();
        let bin_shareholder_address = shareholder.clone().to_bytes();
        let shareholder_address = hex::encode(bin_shareholder_address);

        let stock_key = format!("{}.{}", shareholder_address, stock_hash);
        let stock_key = stock_key.as_bytes();
        let nonce_key = format!("{}.n", shareholder_address);
        let nonce_key = nonce_key.as_bytes();
        let shareholder_nonce = trie.get(&nonce_key);

        match shareholder_nonce {
            // The shareholder's account exists
            Ok(Some(_)) => {
                // Write shares to account
                trie.insert(stock_key, &shares.to_bytes()).unwrap();
            },
            // The shareholder's account does not exist so we create it
            Ok(None) => {
                // Create account by adding writing a `0` nonce
                trie.insert(nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

                // Write shares to account
                trie.insert(stock_key, &shares.to_bytes()).unwrap();
            },
            Err(err) => panic!(err)
        }
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenShares {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> OpenShares {
        OpenShares {
            creator: Arbitrary::arbitrary(g),
            shares: Arbitrary::arbitrary(g),
            share_map: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            address: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            stock_hash: Some(Arbitrary::arbitrary(g)),
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
    use hashdb::Hasher;

    #[test]
    fn apply_it_correctly_creates_a_shares_account() {
        let id = Identity::new();
        let sh1 = Identity::new();
        let sh2 = Identity::new();
        let sh3 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(*id.pkey());
        let cur_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, Address::Normal(creator_addr.clone()), cur_hash, b"10000.0");

        let amount = Balance::from_bytes(b"30.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();
        let shares = Shares::new(1000, 1000000, 60);
        let mut share_map = ShareMap::new();

        share_map.add_shareholder(NormalAddress::from_pkey(*sh1.pkey()), 300);
        share_map.add_shareholder(NormalAddress::from_pkey(*sh2.pkey()), 400);
        share_map.add_shareholder(NormalAddress::from_pkey(*sh3.pkey()), 300);

        let mut tx = OpenShares {
            creator: creator_addr.clone(),
            fee: fee.clone(),
            shares: shares.clone(),
            share_map: share_map.clone(),
            fee_hash: cur_hash,
            amount: amount.clone(),
            currency_hash: cur_hash,
            nonce: 3429,
            address: None,
            stock_hash: None,
            signature: None,
            hash: None
        };

        tx.compute_address();
        tx.compute_stock_hash();
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

        let share_map_key = format!("{}.sm", hex::encode(tx.address.clone().unwrap().to_bytes()));
        let share_map_key = share_map_key.as_bytes();
        let shares_key = format!("{}.s", hex::encode(tx.address.unwrap().to_bytes()));
        let shares_key = shares_key.as_bytes();

        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();
        let bin_receiver_nonce = &trie.get(&receiver_nonce_key).unwrap().unwrap();

        let bin_cur_hash = cur_hash.to_vec();
        let hex_cur_hash = hex::encode(&bin_cur_hash);
        let bin_stock_hash = tx.stock_hash.unwrap().to_vec();
        let hex_stock_hash = hex::encode(&bin_stock_hash);

        let creator_balance_key = format!("{}.{}", hex::encode(&creator_addr.to_bytes()), hex_cur_hash);
        let creator_balance_key = creator_balance_key.as_bytes();

        let balance = Balance::from_bytes(&trie.get(&creator_balance_key).unwrap().unwrap()).unwrap();
        let written_shares = Shares::from_bytes(&trie.get(&shares_key).unwrap().unwrap()).unwrap();
        let written_share_map = ShareMap::from_bytes(&trie.get(&share_map_key).unwrap().unwrap()).unwrap();

        // Check nonces
        assert_eq!(bin_creator_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bin_receiver_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 0]);

        // Verify that the correct amount of funds have been subtracted from the sender
        assert_eq!(balance, Balance::from_bytes(b"10000.0").unwrap() - amount.clone() - fee.clone());

        // Verify shares and share map
        assert_eq!(written_shares, shares);
        assert_eq!(written_share_map, share_map);

        // Verify that shares have been allocated to each shareholder
        for shareholder in share_map.keys() {
            let shares = share_map.get(shareholder.clone()).unwrap();
            let bin_shareholder = shareholder.to_bytes();
            let hex_shareholder = hex::encode(bin_shareholder);
            let cur_key = format!("{}.{}", hex_shareholder, hex_stock_hash);
            let balance = Balance::from_bytes(&trie.get(cur_key.as_bytes()).unwrap().unwrap()).unwrap();
            let expected_balance = format!("{}.0", shares);

            assert_eq!(balance, Balance::from_bytes(expected_balance.as_bytes()).unwrap());
        }
    }

    quickcheck! {
        fn serialize_deserialize(tx: OpenShares) -> bool {
            tx == OpenShares::from_bytes(&OpenShares::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: OpenShares) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            address: ShareholdersAddress,
            shares: Shares,
            share_map: ShareMap,
            amount: Balance,
            fee: Balance,
            hashes: (Hash, Hash, Hash),
            nonce: u64
        ) -> bool {
            let id = Identity::new();
            let (currency_hash, fee_hash, stock_hash) = hashes;

            let mut tx = OpenShares {
                creator: NormalAddress::from_pkey(*id.pkey()),
                shares: shares,
                share_map: share_map,
                amount: amount,
                currency_hash: currency_hash,
                fee: fee,
                fee_hash: fee_hash,
                nonce: nonce,
                stock_hash: Some(stock_hash),
                address: Some(address),
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}