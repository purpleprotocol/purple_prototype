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

use account::{Balance, MultiSig, NormalAddress, ShareMap, ShareholdersAddress, Shares};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, SecretKey as Sk};
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IssueShares {
    issuer: ShareholdersAddress,
    receiver: NormalAddress,
    shares: u32,
    fee_hash: Hash,
    fee: Balance,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<MultiSig>,
}

impl IssueShares {
    pub const TX_TYPE: u8 = 7;

    /// Validates the transaction against the provided state.
    pub fn validate(&mut self, trie: &TrieDBMut<BlakeDbHasher, Codec>) -> bool {
        let bin_issuer = &self.issuer.to_bytes();
        let _bin_receiver = &self.receiver.to_bytes();
        let bin_fee_hash = &self.fee_hash.to_vec();
        let shares = self.shares;
        let issuer = hex::encode(bin_issuer);
        let zero = Balance::from_bytes(b"0.0").unwrap();

        // You cannot issue 0 shares
        if shares < 1 {
            return false;
        }

        let shares_key = format!("{}.s", issuer);
        let share_map_key = format!("{}.sm", issuer);
        let shares_key = shares_key.as_bytes();
        let share_map_key = share_map_key.as_bytes();

        let written_shares = match trie.get(&shares_key) {
            Ok(Some(result)) => Shares::from_bytes(&result).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        let share_map = match trie.get(&share_map_key) {
            Ok(Some(result)) => ShareMap::from_bytes(&result).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        if !self.verify_multi_sig_shares(written_shares.required_percentile, share_map) {
            return false;
        }

        // Convert fee hash to string
        let fee_hash = hex::encode(bin_fee_hash);

        let issuer_fee_key = format!("{}.{}", issuer, fee_hash);
        let issuer_fee_key = issuer_fee_key.as_bytes();

        // Calculate shares key
        //
        // The keys of shares objects have the following format:
        // `<account-address>.s`
        let shares_key = format!("{}.s", issuer);
        let shares_key = shares_key.as_bytes();

        let mut balance = match trie.get(&issuer_fee_key) {
            Ok(Some(balance)) => Balance::from_bytes(&balance).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        balance -= self.fee.clone();

        let written_shares = match trie.get(&shares_key) {
            Ok(Some(shares)) => Shares::from_bytes(&shares).unwrap(),
            Ok(None) => return false,
            Err(err) => panic!(err),
        };

        shares + written_shares.issued_shares <= written_shares.authorized_shares && balance >= zero
    }

    /// Applies the open shares transaction to the provided database.
    ///
    /// This function will panic if the `issuer` account does not exist.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_issuer = &self.issuer.to_bytes();
        let bin_receiver = &self.receiver.to_bytes();
        let bin_fee_hash = &self.fee_hash.to_vec();
        let shares = &self.shares;

        // Convert addresses to strings
        let issuer = hex::encode(bin_issuer);
        let receiver = hex::encode(bin_receiver);

        // Convert fee hash to string
        let fee_hash = hex::encode(bin_fee_hash);

        let issuer_fee_key = format!("{}.{}", issuer, fee_hash);
        let issuer_fee_key = issuer_fee_key.as_bytes();

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let issuer_nonce_key = format!("{}.n", issuer);
        let issuer_nonce_key = issuer_nonce_key.as_bytes();

        // Calculate shares and share map keys
        //
        // The keys of shares objects have the following format:
        // `<account-address>.s`
        //
        // The keys of share map objects have the following format:
        // `<account-address>.sm`
        let shares_key = format!("{}.s", issuer);
        let share_map_key = format!("{}.sm", issuer);
        let shares_key = shares_key.as_bytes();
        let share_map_key = share_map_key.as_bytes();

        // Calculate stock hash key
        //
        // The key of a shareholders account's stock hash has the following format:
        // `<account-address>.sh`
        let stock_hash_key = format!("{}.sh", issuer);
        let stock_hash_key = stock_hash_key.as_bytes();

        // Retrieve stock hash
        let stock_hash = trie.get(&stock_hash_key).unwrap().unwrap();
        let stock_hash = hex::encode(stock_hash);

        // Calculate receiver shares key
        let receiver_shares_key = format!("{}.{}", receiver, stock_hash);
        let receiver_shares_key = receiver_shares_key.as_bytes();

        // Retrieve serialized nonce
        let bin_issuer_nonce = &trie.get(&issuer_nonce_key).unwrap().unwrap();

        // Read the nonce of the issuer
        let mut nonce = decode_be_u64!(bin_issuer_nonce).unwrap();

        // Increment issuer nonce
        nonce += 1;

        let nonce: Vec<u8> = encode_be_u64!(nonce);

        let mut issuer_balance = unwrap!(
            Balance::from_bytes(&unwrap!(
                trie.get(&issuer_fee_key).unwrap(),
                "The issuer does not have an entry for the given currency"
            )),
            "Invalid stored balance format"
        );

        let mut share_map = unwrap!(
            ShareMap::from_bytes(&unwrap!(
                trie.get(&share_map_key).unwrap(),
                "The issuer does not have a stored share map"
            )),
            "Invalid stored share map"
        );

        let mut shares_obj = unwrap!(
            Shares::from_bytes(&unwrap!(
                trie.get(&shares_key).unwrap(),
                "The issuer does not have a stored shares object"
            )),
            "Invalid stored shares"
        );

        let receiver_balance: Vec<u8> = match trie.get(&receiver_shares_key) {
            // The receiver is already a shareholder
            Ok(Some(balance)) => {
                let balance = decode_be_u32!(balance).unwrap();
                let result = balance + shares;

                encode_be_u32!(result)
            }
            Ok(None) => encode_be_u32!(*shares),
            Err(err) => panic!(err),
        };

        // Subtract fee from issuer balance
        issuer_balance -= self.fee.clone();

        // Add shares to receiver
        share_map.issue_shares(self.receiver.clone(), *shares);
        shares_obj.issue_shares(*shares);

        // Update trie
        trie.insert(issuer_nonce_key, &nonce).unwrap();
        trie.insert(issuer_fee_key, &issuer_balance.to_bytes())
            .unwrap();
        trie.insert(receiver_shares_key, &receiver_balance).unwrap();
        trie.insert(share_map_key, &share_map.to_bytes()).unwrap();
        trie.insert(shares_key, &shares_obj.to_bytes()).unwrap();
    }

    /// Signs the transaction with the given secret key.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, &skey);

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
    /// 1) Transaction type(7)      - 8bits
    /// 2) Fee length               - 8bits
    /// 3) Signature length         - 16bits
    /// 4) Amount of issued shares  - 32bits
    /// 5) Issuer                   - 33byte binary
    /// 6) Receiver                 - 33byte binary
    /// 7) Fee hash                 - 32byte binary
    /// 8) Hash                     - 32byte binary
    /// 9) Fee                      - Binary of fee length
    /// 10) Signature               - Binary of signature length
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

        let issuer = &self.issuer.to_bytes();
        let receiver = &self.receiver.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let shares = &self.shares;
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();
        buffer.write_u32::<BigEndian>(*shares).unwrap();

        buffer.append(&mut issuer.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut signature);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<IssueShares, &'static str> {
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

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
        };

        rdr.set_position(4);

        let shares = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err("Bad shares");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..8).collect();

        let issuer = if buf.len() > 33 as usize {
            let issuer_vec: Vec<u8> = buf.drain(..33).collect();

            match ShareholdersAddress::from_bytes(&issuer_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 33 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&receiver_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
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

        let issue_shares = IssueShares {
            issuer: issuer,
            receiver: receiver,
            shares: shares,
            fee_hash: fee_hash,
            fee: fee,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(issue_shares)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(_trie: &mut TrieDBMut<BlakeDbHasher, Codec>, _sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &IssueShares) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut issuer = obj.issuer.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let shares = obj.shares;
    let mut fee = obj.fee.to_bytes();

    buf.write_u32::<BigEndian>(shares).unwrap();

    // Compose data to hash
    buf.append(&mut issuer);
    buf.append(&mut receiver);
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &IssueShares) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut issuer = obj.issuer.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let shares = obj.shares;
    let mut fee = obj.fee.to_bytes();

    buf.write_u32::<BigEndian>(shares).unwrap();

    // Compose data to sign
    buf.append(&mut issuer);
    buf.append(&mut receiver);
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for IssueShares {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> IssueShares {
        IssueShares {
            issuer: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            shares: Arbitrary::arbitrary(g),
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
    use account::{Address, NormalAddress};
    use crypto::{Identity, PublicKey as Pk};
    use crate::OpenShares;

    #[test]
    fn validate() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let issuer_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let shares = Shares::new(1000, 1000000, 60);
        let mut share_map = ShareMap::new();

        share_map.add_shareholder(NormalAddress::from_pkey(*id2.pkey()), 1000);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");

        // Create shares account
        let mut open_shares = OpenShares {
            creator: creator_norm_address.clone(),
            share_map: share_map,
            shares: shares.clone(),
            asset_hash: fee_hash.clone(),
            fee_hash: fee_hash.clone(),
            amount: Balance::from_bytes(b"100.0").unwrap(),
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

        let mut tx = IssueShares {
            issuer: open_shares.address.unwrap(),
            receiver: issuer_norm_addr.clone(),
            shares: 999000,
            fee: Balance::from_bytes(b"10.0").unwrap(),
            fee_hash: fee_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(tx.validate(&trie));
    }

    #[test]
    fn validate_bad_issued_shares() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let issuer_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let shares = Shares::new(1000, 1000000, 60);
        let mut share_map = ShareMap::new();

        share_map.add_shareholder(NormalAddress::from_pkey(*id2.pkey()), 1000);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");

        // Create shares account
        let mut open_shares = OpenShares {
            creator: creator_norm_address.clone(),
            share_map: share_map,
            shares: shares.clone(),
            asset_hash: fee_hash.clone(),
            fee_hash: fee_hash.clone(),
            amount: Balance::from_bytes(b"100.0").unwrap(),
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

        let mut tx = IssueShares {
            issuer: open_shares.address.unwrap(),
            receiver: issuer_norm_addr.clone(),
            shares: 999001,
            fee: Balance::from_bytes(b"10.0").unwrap(),
            fee_hash: fee_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_bad_fee() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let issuer_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let shares = Shares::new(1000, 1000000, 60);
        let mut share_map = ShareMap::new();

        share_map.add_shareholder(NormalAddress::from_pkey(*id2.pkey()), 1000);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");

        // Create shares account
        let mut open_shares = OpenShares {
            creator: creator_norm_address.clone(),
            share_map: share_map,
            shares: shares.clone(),
            asset_hash: fee_hash.clone(),
            fee_hash: fee_hash.clone(),
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
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

        let mut tx = IssueShares {
            issuer: open_shares.address.unwrap(),
            receiver: issuer_norm_addr.clone(),
            shares: 999900,
            fee: Balance::from_bytes(b"100000.0").unwrap(),
            fee_hash: fee_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn validate_zero() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let issuer_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let shares = Shares::new(1000, 1000000, 60);
        let mut share_map = ShareMap::new();

        share_map.add_shareholder(NormalAddress::from_pkey(*id2.pkey()), 1000);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");

        // Create shares account
        let mut open_shares = OpenShares {
            creator: creator_norm_address.clone(),
            share_map: share_map,
            shares: shares.clone(),
            asset_hash: fee_hash.clone(),
            fee_hash: fee_hash.clone(),
            amount: Balance::from_bytes(b"100.0").unwrap(),
            fee: Balance::from_bytes(b"10.0").unwrap(),
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

        let mut tx = IssueShares {
            issuer: open_shares.address.unwrap(),
            receiver: issuer_norm_addr.clone(),
            shares: 0,
            fee: Balance::from_bytes(b"10.0").unwrap(),
            fee_hash: fee_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();

        assert!(!tx.validate(&trie));
    }

    #[test]
    fn apply_it_issues_shares_and_adds_them_to_the_creator() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = Address::normal_from_pkey(*id.pkey());
        let creator_norm_address = NormalAddress::from_pkey(*id.pkey());
        let issuer_norm_addr = NormalAddress::from_pkey(*id2.pkey());
        let fee_hash = crypto::hash_slice(b"Test currency 2");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let mut shares = Shares::new(1000, 1000000, 60);
        let mut share_map = ShareMap::new();

        share_map.add_shareholder(NormalAddress::from_pkey(*id2.pkey()), 1000);

        // Manually initialize creator balance
        test_helpers::init_balance(&mut trie, creator_addr.clone(), fee_hash, b"10000.0");

        // Create shares account
        let mut open_shares = OpenShares {
            creator: creator_norm_address.clone(),
            share_map: share_map,
            shares: shares.clone(),
            asset_hash: fee_hash.clone(),
            fee_hash: fee_hash.clone(),
            amount: Balance::from_bytes(b"100.0").unwrap(),
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

        let mut tx = IssueShares {
            issuer: open_shares.address.unwrap(),
            receiver: issuer_norm_addr.clone(),
            shares: 1000,
            fee: Balance::from_bytes(b"10.0").unwrap(),
            fee_hash: fee_hash,
            signature: None,
            hash: None,
        };

        tx.sign(id2.skey().clone());
        tx.hash();
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let stock_hash = hex::encode(open_shares.stock_hash.unwrap().to_vec());
        let address = hex::encode(open_shares.address.unwrap().to_bytes());
        let receiver_addr = hex::encode(issuer_norm_addr.clone().to_bytes());

        let shares_key = format!("{}.s", address);
        let shares_key = shares_key.as_bytes();
        let share_map_key = format!("{}.sm", address);
        let share_map_key = share_map_key.as_bytes();
        let stock_balance_key = format!("{}.{}", receiver_addr, stock_hash);
        let stock_balance_key = stock_balance_key.as_bytes();

        let written_shares = trie.get(&shares_key).unwrap().unwrap();
        let written_shares = Shares::from_bytes(&written_shares).unwrap();
        let written_share_map = trie.get(&share_map_key).unwrap().unwrap();
        let written_share_map = ShareMap::from_bytes(&written_share_map).unwrap();
        let written_stock_balance = trie.get(&stock_balance_key).unwrap().unwrap();
        let written_stock_balance = decode_be_u32!(written_stock_balance).unwrap();

        shares.issue_shares(1000);

        assert_eq!(written_stock_balance, 2000);
        assert_eq!(written_share_map.get(issuer_norm_addr).unwrap(), 2000);
        assert_eq!(written_shares, shares);
    }

    quickcheck! {
        fn serialize_deserialize(tx: IssueShares) -> bool {
            tx == IssueShares::from_bytes(&IssueShares::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: IssueShares) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_multi_signature_shares(
            receiver: NormalAddress,
            fee: Balance,
            shares: u32,
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

            let mut tx = IssueShares {
                issuer: ShareholdersAddress::compute(&addresses, NormalAddress::from_pkey(*creator_id.pkey()), 4314),
                receiver: receiver,
                shares: shares,
                fee: fee,
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
