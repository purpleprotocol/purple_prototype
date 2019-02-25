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

use account::{Balance, MultiSig, NormalAddress, ShareMap, ShareholdersAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, SecretKey as Sk};
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use rust_decimal::Decimal;
use std::io::Cursor;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Pay {
    payer: ShareholdersAddress,
    asset_hash: Hash,
    fee_hash: Hash,
    amount: Balance,
    fee: Balance,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<MultiSig>,
}

impl Pay {
    pub const TX_TYPE: u8 = 4;

    /// Applies the open shares transaction to the provided database.
    ///
    /// This function will panic if the `payer` account does not exist.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_payer = &self.payer.to_bytes();
        let bin_asset_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();

        // Convert address to string
        let payer = hex::encode(bin_payer);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_asset_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        let payer_cur_key = format!("{}.{}", payer, asset_hash);
        let payer_cur_key = payer_cur_key.as_bytes();
        let payer_fee_key = format!("{}.{}", payer, fee_hash);
        let payer_fee_key = payer_fee_key.as_bytes();

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let payer_nonce_key = format!("{}.n", payer);
        let payer_nonce_key = payer_nonce_key.as_bytes();

        // Calculate share map key
        // The keys of share map objects have the following format:
        // `<account-address>.sm`
        let share_map_key = format!("{}.sm", payer);
        let share_map_key = share_map_key.as_bytes();

        // Retrieve serialized nonce
        let bin_payer_nonce = &trie.get(&payer_nonce_key).unwrap().unwrap();

        // Read the nonce of the payer
        let mut nonce = decode_be_u64!(bin_payer_nonce).unwrap();

        // Increment payer nonce
        nonce += 1;

        let nonce: Vec<u8> = encode_be_u64!(nonce);

        if asset_hash == fee_hash {
            let mut payer_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&payer_cur_key).unwrap(),
                    "The payer does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            let share_map = unwrap!(
                ShareMap::from_bytes(&unwrap!(
                    trie.get(&share_map_key).unwrap(),
                    "The payer does not have a stored share map"
                )),
                "Invalid stored share map"
            );

            // Subtract fee from payer balance
            payer_balance -= self.fee.clone();

            // Subtract amount from payer balance
            payer_balance -= self.amount.clone();

            let issued_shares = share_map.issued_shares;

            // Add dividend to each shareholder
            for (k, v) in share_map {
                pay_dividend(trie, &self.amount, &self.asset_hash, k, v, issued_shares);
            }

            // Update trie
            trie.insert(payer_nonce_key, &nonce).unwrap();
            trie.insert(payer_cur_key, &payer_balance.to_bytes())
                .unwrap();
        } else {
            let mut payer_cur_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&payer_cur_key).unwrap(),
                    "The payer does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            let mut payer_fee_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&payer_fee_key).unwrap(),
                    "The payer does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            let share_map = unwrap!(
                ShareMap::from_bytes(&unwrap!(
                    trie.get(&share_map_key).unwrap(),
                    "The payer does not have a stored share map"
                )),
                "Invalid stored share map"
            );

            // Subtract fee from payer balance
            payer_fee_balance -= self.fee.clone();

            // Subtract amount from payer balance
            payer_cur_balance -= self.amount.clone();

            let issued_shares = share_map.issued_shares;

            // Add dividend to each shareholder
            for (k, v) in share_map {
                pay_dividend(trie, &self.amount, &self.asset_hash, k, v, issued_shares);
            }

            // Update trie
            trie.insert(payer_nonce_key, &nonce).unwrap();
            trie.insert(payer_cur_key, &payer_cur_balance.to_bytes())
                .unwrap();
            trie.insert(payer_fee_key, &payer_fee_balance.to_bytes())
                .unwrap();
        }
    }

    /// Signs the transaction with the given secret key.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        match self.signature {
            Some(ref mut sig) => {
                // Append signature to the multi sig struct
                sig.append_sig(signature);
            }
            None => {
                // Create a multi signature
                let result = MultiSig::from_sig(signature);

                // Attach signature to struct
                self.signature = Some(result);
            }
        };
    }

    /// Verifies the multi signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_multi_sig_shares(
        &mut self,
        required_percentile: u8,
        share_map: ShareMap,
    ) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => sig.verify_shares(&message, required_percentile, share_map),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(4)      - 8bits
    /// 2) Amount length            - 8bits
    /// 3) Fee length               - 8bits
    /// 4) Signature length         - 16bits
    /// 5) Payer                    - 33byte binary
    /// 6) Currency hash            - 32byte binary
    /// 7) Fee hash                 - 32byte binary
    /// 8) Hash                     - 32byte binary
    /// 9) Amount                   - Binary of amount length
    /// 10) Fee                     - Binary of fee length
    /// 11) Signature               - Binary of signature length
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

        let payer = &self.payer.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();

        let amount_len = amount.len();
        let fee_len = fee.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();

        buffer.append(&mut payer.to_vec());
        buffer.append(&mut asset_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut signature);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Pay, &'static str> {
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
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..5).collect();

        let payer = if buf.len() > 33 as usize {
            let payer_vec: Vec<u8> = buf.drain(..33).collect();

            match ShareholdersAddress::from_bytes(&payer_vec) {
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
                Err(_) => return Err("Bad fee"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() == signature_len as usize {
            let sig_vec: Vec<u8> = buf.drain(..signature_len as usize).collect();

            match MultiSig::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let pay = Pay {
            payer: payer,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            amount: amount,
            fee: fee,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(pay)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn pay_dividend(
    trie: &mut TrieDBMut<BlakeDbHasher, Codec>,
    amount: &Balance,
    asset_hash: &Hash,
    address: NormalAddress,
    address_shares: u32,
    issued_shares: u32,
) {
    let address = hex::encode(&address.to_bytes());
    let asset_hash = hex::encode(asset_hash.to_vec());

    // Calculate balance key
    let balance_key = format!("{}.{}", address, asset_hash);
    let balance_key = balance_key.as_bytes();

    // Convert shares to decimals
    let address_shares = format!("{}.0", address_shares);
    let address_shares = Decimal::from_str(&address_shares).unwrap();
    let issued_shares = format!("{}.0", issued_shares);
    let issued_shares = Decimal::from_str(&issued_shares).unwrap();
    let one_hundred = Decimal::from_str("100.0").unwrap();

    // Calculate address percentage
    let percentage = (address_shares / issued_shares) * one_hundred;
    let amount_deci = amount.to_inner();

    // Calculate amount to be paid
    let amount = (percentage / one_hundred) * amount_deci;
    let amount = format!("{}", amount);
    let amount = amount.as_bytes();
    let amount = Balance::from_bytes(amount).unwrap().to_bytes();

    // Update trie
    trie.insert(balance_key, &amount).unwrap();
}

fn assemble_hash_message(obj: &Pay) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut payer = obj.payer.to_bytes();
    let asset_hash = &obj.asset_hash.0;
    let fee_hash = &obj.fee_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();

    // Compose data to hash
    buf.append(&mut payer);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &Pay) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut payer = obj.payer.to_bytes();
    let asset_hash = &obj.asset_hash.0;
    let fee_hash = &obj.fee_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();

    // Compose data to sign
    buf.append(&mut payer);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Pay {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Pay {
        Pay {
            payer: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use account::{Address, NormalAddress, Shares};
    use crypto::{Identity, PublicKey as Pk};
    use OpenShares;

    #[test]
    fn apply_it_pays_dividends() {
        let id = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();
        let id4 = Identity::new();
        let id5 = Identity::new();

        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());

        // Create shareholders addresses and skeys
        let sh1_addr = NormalAddress::from_pkey(*id2.pkey());
        let sh1_skey = id2.skey().clone();
        let sh2_addr = NormalAddress::from_pkey(*id3.pkey());
        let sh2_skey = id3.skey().clone();
        let sh3_addr = NormalAddress::from_pkey(*id4.pkey());
        let sh3_skey = id4.skey().clone();
        let sh4_addr = NormalAddress::from_pkey(*id5.pkey());
        let sh4_skey = id5.skey().clone();

        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let shares = Shares::new(4000, 1000000, 60);
        let mut share_map = ShareMap::new();

        share_map.add_shareholder(sh1_addr, 1000);
        share_map.add_shareholder(sh2_addr, 1000);
        share_map.add_shareholder(sh3_addr, 1000);
        share_map.add_shareholder(sh4_addr, 1000);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, creator_addr, asset_hash, b"10000.0");

        // Create shares account
        let mut open_shares = OpenShares {
            creator: creator_norm_address,
            share_map: share_map,
            shares: shares,
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            amount: Balance::from_bytes(b"1000.0").unwrap(),
            fee: Balance::from_bytes(b"30.0").unwrap(),
            nonce: 1,
            address: None,
            stock_hash: None,
            signature: None,
            hash: None,
        };

        open_shares.compute_address();
        open_shares.compute_stock_hash();
        open_shares.sign(id2.skey().clone());
        open_shares.hash();
        open_shares.apply(&mut trie);

        let mut tx = Pay {
            payer: open_shares.address.unwrap(),
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
            asset_hash: asset_hash,
            fee_hash: asset_hash,
            signature: None,
            hash: None,
        };

        tx.sign(sh1_skey);
        tx.sign(sh2_skey);
        tx.sign(sh3_skey);
        tx.sign(sh4_skey);
        tx.hash();
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let asset_hash = hex::encode(&asset_hash.to_vec());
        let sh1_addr = hex::encode(&sh1_addr.to_bytes());
        let sh2_addr = hex::encode(&sh2_addr.to_bytes());
        let sh3_addr = hex::encode(&sh3_addr.to_bytes());
        let sh4_addr = hex::encode(&sh4_addr.to_bytes());

        let sh1_balance_key = format!("{}.{}", sh1_addr, asset_hash);
        let sh1_balance_key = sh1_balance_key.as_bytes();
        let sh2_balance_key = format!("{}.{}", sh2_addr, asset_hash);
        let sh2_balance_key = sh2_balance_key.as_bytes();
        let sh3_balance_key = format!("{}.{}", sh3_addr, asset_hash);
        let sh3_balance_key = sh3_balance_key.as_bytes();
        let sh4_balance_key = format!("{}.{}", sh4_addr, asset_hash);
        let sh4_balance_key = sh4_balance_key.as_bytes();

        let sh1_balance = trie.get(sh1_balance_key).unwrap().unwrap();
        let sh2_balance = trie.get(sh2_balance_key).unwrap().unwrap();
        let sh3_balance = trie.get(sh3_balance_key).unwrap().unwrap();
        let sh4_balance = trie.get(sh4_balance_key).unwrap().unwrap();

        assert_eq!(
            Balance::from_bytes(&sh1_balance).unwrap(),
            Balance::from_bytes(b"25.0").unwrap()
        );
        assert_eq!(
            Balance::from_bytes(&sh2_balance).unwrap(),
            Balance::from_bytes(b"25.0").unwrap()
        );
        assert_eq!(
            Balance::from_bytes(&sh3_balance).unwrap(),
            Balance::from_bytes(b"25.0").unwrap()
        );
        assert_eq!(
            Balance::from_bytes(&sh4_balance).unwrap(),
            Balance::from_bytes(b"25.0").unwrap()
        );
    }

    quickcheck! {
        fn serialize_deserialize(tx: Pay) -> bool {
            tx == Pay::from_bytes(&Pay::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: Pay) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_multi_signature_shares(
            amount: Balance,
            fee: Balance,
            asset_hash: Hash,
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

            let mut tx = Pay {
                payer: ShareholdersAddress::compute(&addresses, NormalAddress::from_pkey(*creator_id.pkey()), 4314),
                amount: amount,
                fee: fee,
                asset_hash: asset_hash,
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
