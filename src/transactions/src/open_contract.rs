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

use account::{Address, Balance, ContractAddress, NormalAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{ShortHash, Hash, PublicKey as Pk, SecretKey as Sk, Signature};
use patricia_trie::{TrieDBMut, TrieDB, TrieMut, Trie};
use persistence::{BlakeDbHasher, Codec};
use rand::Rng;
use std::io::Cursor;
use std::str;

#[derive(Debug, Clone, PartialEq)]
pub struct OpenContract {
    pub(crate) creator: Pk,
    pub(crate) next_address: NormalAddress,
    pub(crate) code: Vec<u8>,
    pub(crate) default_state: Vec<u8>,
    pub(crate) amount: Balance,
    pub(crate) asset_hash: Hash,
    pub(crate) fee: Balance,
    pub(crate) fee_hash: Hash,
    pub(crate) self_payable: bool,
    pub(crate) nonce: u64,
    
    pub(crate) address: Option<ContractAddress>,
    
    pub(crate) hash: Option<Hash>,
    
    pub(crate) signature: Option<Signature>,
}

impl OpenContract {
    pub const TX_TYPE: u8 = 2;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<BlakeDbHasher, Codec>) -> bool {
        unimplemented!();
    }

    /// Applies the open contract transaction to the provided database.
    ///
    /// This function will panic if the `creator` account does not exist
    /// or if the account address already exists in the ledger.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_address = self.address.as_ref().unwrap().as_bytes();
        let bin_asset_hash = &self.asset_hash.0;
        let bin_fee_hash = &self.fee_hash.0;
        let self_payable: Vec<u8> = if self.self_payable { vec![1] } else { vec![0] };
        let creator_addr = NormalAddress::from_pkey(&self.creator);
        let code = &self.code;
        let default_state = &self.default_state;

        // Calculate address mapping key
        //
        // An address mapping is a mapping between
        // the account's signing address and an 
        // account's receiving address.
        //
        // They key of the address mapping has the following format:
        // `<signing-address>.am`
        let creator_addr_mapping_key = [creator_addr.as_bytes(), &b".am"[..]].concat();
        let next_addr_mapping_key = [self.next_address.as_bytes(), &b".am"[..]].concat();

        // Retrieve creator account permanent address
        let creator_perm_addr = trie.get(&creator_addr_mapping_key).unwrap().unwrap();
        let creator_perm_addr = NormalAddress::from_bytes(&creator_perm_addr).unwrap();

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let creator_nonce_key = [creator_perm_addr.as_bytes(), &b".n"[..]].concat();
        let address_nonce_key = [bin_address, &b".n"[..]].concat();

        #[cfg(test)]
        {
            if let Ok(Some(_)) = trie.get(&address_nonce_key) {
                panic!("The created address already exists in the ledger!");
            }
        }

        // Calculate code key
        //
        // The key of a contract's code has the following format:
        // `<contract-address>.c`
        let code_key = [bin_address, &b".c"[..]].concat();

        // Calculate state key
        //
        // The key of a contract's state has the following format:
        // `<contract-address>.q`
        let state_key = [bin_address, &b".q"[..]].concat();

        // Calculate self payable key
        //
        // The key of a contract's self payable entry has the following format:
        // `<contract-address>.y`
        let self_payable_key = [bin_address, &b".y"[..]].concat();

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
        let creator_cur_key = [creator_perm_addr.as_bytes(), &b"."[..], bin_asset_hash].concat();
        let creator_fee_key = [creator_perm_addr.as_bytes(), &b"."[..], bin_fee_hash].concat();
        let address_cur_key = [bin_address, &b"."[..], bin_asset_hash].concat();

        if bin_fee_hash == bin_asset_hash {
            // The transaction's fee is paid in the same currency
            // that is being transferred, so we only retrieve one
            // balance.
            let mut creator_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&creator_cur_key).unwrap(),
                    "The creator does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from creator balance
            creator_balance -= self.fee.clone();

            // Subtract amount transferred from creator balance
            creator_balance -= self.amount.clone();

            let receiver_balance = self.amount.clone();

            // Update trie
            trie.insert(&self_payable_key, &self_payable).unwrap();
            trie.insert(&state_key, default_state).unwrap();
            trie.insert(&code_key, code).unwrap();
            trie.insert(&creator_cur_key, &creator_balance.to_bytes())
                .unwrap();
            trie.insert(&address_cur_key, &receiver_balance.to_bytes())
                .unwrap();
            trie.insert(&creator_nonce_key, &nonce_buf).unwrap();
            trie.insert(&address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();

            // Update creator address mapping
            trie.remove(&creator_addr_mapping_key).unwrap();
            trie.insert(&next_addr_mapping_key, creator_perm_addr.as_bytes()).unwrap();
        } else {
            // The transaction's fee is paid in a different currency
            // than the one being transferred so we retrieve both balances.
            let mut creator_cur_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&creator_cur_key).unwrap(),
                    "The creator does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            let mut creator_fee_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&creator_fee_key).unwrap(),
                    "The creator does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from creator
            creator_fee_balance -= self.fee.clone();

            // Subtract amount transferred from creator
            creator_cur_balance -= self.amount.clone();

            let receiver_balance = self.amount.clone();

            // Update trie
            trie.insert(&self_payable_key, &self_payable).unwrap();
            trie.insert(&state_key, default_state).unwrap();
            trie.insert(&code_key, code).unwrap();
            trie.insert(&creator_cur_key, &creator_cur_balance.to_bytes())
                .unwrap();
            trie.insert(&creator_fee_key, &creator_fee_balance.to_bytes())
                .unwrap();
            trie.insert(&address_cur_key, &receiver_balance.to_bytes())
                .unwrap();
            trie.insert(&creator_nonce_key, &nonce_buf).unwrap();
            trie.insert(&address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();

            // Update creator address mapping
            trie.remove(&creator_addr_mapping_key).unwrap();
            trie.insert(&next_addr_mapping_key, creator_perm_addr.as_bytes()).unwrap();
        }
    }

    /// Computes the address of the opened contract.
    ///
    /// A contract's address is computed by appending the creator's
    /// address together with the code and the default state to
    /// the creator's nonce. The address is the hash of the result.
    pub fn compute_address(&mut self) {
        let mut buf: Vec<u8> = Vec::new();

        let code = &self.code;
        let state = &self.default_state;
        let nonce = &self.nonce;

        buf.write_u64::<BigEndian>(*nonce).unwrap();
        buf.extend_from_slice(&self.creator.0);
        buf.extend_from_slice(&code);
        buf.extend_from_slice(&state);

        let result = crypto::hash_slice(&buf);
        self.address = Some(ContractAddress::new(result));
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
            Some(ref sig) => crypto::verify(&message, sig, &self.creator),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(2)      - 8bits
    /// 2) Self payable             - 8bits
    /// 3) Amount length            - 8bits
    /// 4) Fee length               - 8bits
    /// 5) State length             - 16bits
    /// 6) Code length              - 16bits
    /// 7) Nonce                    - 64bits
    /// 8) Owner                    - 32byte binary
    /// 9) Address                  - 33byte binary
    /// 10) Next address            - 33byte binary
    /// 11) Currency hash           - 32byte binary
    /// 12) Fee hash                - 32byte binary
    /// 13) Signature               - 64byte binary
    /// 14) Amount                  - Binary of amount length
    /// 15) Fee                     - Binary of fee length
    /// 16) Default state           - Binary of state length
    /// 17) Code                    - Binary of code length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let address = if let Some(address) = &self.address {
            address.to_bytes()
        } else {
            return Err("Address field is missing");
        };

        let signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let self_payable: u8 = if self.self_payable { 1 } else { 0 };
        let code = &self.code;
        let default_state = &self.default_state;
        let amount = self.amount.to_bytes();
        let fee = self.fee.to_bytes();
        let nonce = &self.nonce;

        let amount_len = amount.len();
        let fee_len = fee.len();
        let code_len = code.len();
        let state_len = default_state.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(self_payable).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(state_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(code_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.extend_from_slice(&self.creator.0);
        buffer.extend_from_slice(&address);
        buffer.extend_from_slice(self.next_address.as_bytes());
        buffer.extend_from_slice(&self.asset_hash.0);
        buffer.extend_from_slice(&self.fee_hash.0);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(&amount);
        buffer.extend_from_slice(&fee);
        buffer.extend_from_slice(&default_state);
        buffer.extend_from_slice(&code);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<OpenContract, &'static str> {
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

        let self_payable = if let Ok(result) = rdr.read_u8() {
            match result {
                0 => false,
                1 => true,
                _ => return Err("Invalid self payable field"),
            }
        } else {
            return Err("Bad self payable field");
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

        let state_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad state len");
        };

        rdr.set_position(6);

        let code_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad code len");
        };

        rdr.set_position(8);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..16).collect();

        let creator = if buf.len() > 32 as usize {
            let creator_vec: Vec<u8> = buf.drain(..32).collect();
            let mut creator_bytes = [0; 32];
            creator_bytes.copy_from_slice(&creator_vec);

            Pk(creator_bytes)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the creator field");
        };

        let address = if buf.len() > 33 as usize {
            let address_vec: Vec<u8> = buf.drain(..33).collect();

            match ContractAddress::from_bytes(&address_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the creator field");
        };

        let next_address = if buf.len() > 33 as usize {
            let next_address_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&next_address_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the next address field");
        };

        let asset_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the fee hash field");
        };

        let fee_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the fee hash field");
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64 as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size of the signature field");
        };

        let amount = if buf.len() >= amount_len as usize {
            let amount_vec: Vec<u8> = buf.drain(..amount_len as usize).collect();

            match Balance::from_bytes(&amount_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad amount"),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the fee field");
        };

        let fee = if buf.len() >= fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad fee"),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the fee field");
        };

        let default_state = if buf.len() >= state_len as usize {
            buf.drain(..state_len as usize).collect()
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the default state field");
        };

        let code = if buf.len() == code_len as usize {
            buf.drain(..code_len as usize).collect()
        } else {
            return Err("Incorrect packet structure! Buffer size is not equal with the size for the code field");
        };

        let mut open_contract = OpenContract {
            creator,
            next_address,
            amount,
            asset_hash,
            fee_hash,
            fee,
            default_state,
            self_payable,
            nonce,
            code,
            address: Some(address),
            hash: None,
            signature: Some(signature),
        };

        open_contract.compute_hash();
        Ok(open_contract)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &OpenContract) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let self_payable: u8 = if obj.self_payable { 1 } else { 0 };
    let contract_address = obj.address.as_ref().unwrap().to_bytes();
    let code = &obj.code;
    let default_state = &obj.default_state;
    let amount = obj.amount.to_bytes();
    let fee = obj.fee.to_bytes();

    buf.write_u8(self_payable).unwrap();
    buf.write_u64::<BigEndian>(obj.nonce).unwrap();

    // Compose data to hash
    buf.extend_from_slice(&obj.creator.0);
    buf.extend_from_slice(&obj.next_address.to_bytes());
    buf.extend_from_slice(&contract_address);
    buf.extend_from_slice(&obj.asset_hash.0);
    buf.extend_from_slice(&obj.fee_hash.0);
    buf.extend_from_slice(&code);
    buf.extend_from_slice(&default_state);
    buf.extend_from_slice(&amount);
    buf.extend_from_slice(&fee);
    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenContract {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> OpenContract {
        let (pk, _) = crypto::gen_keypair();
        let mut tx = OpenContract {
            creator: pk,
            next_address: Arbitrary::arbitrary(g),
            code: Arbitrary::arbitrary(g),
            default_state: Arbitrary::arbitrary(g),
            self_payable: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            address: Some(Arbitrary::arbitrary(g)),
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
    use account::NormalAddress;
    use crypto::Identity;

    #[test]
    fn apply_it_opens_a_contract() {
        let id = Identity::new();
        let id2 = Identity::new();
        let creator_addr = NormalAddress::from_pkey(id.pkey());
        let next_address = NormalAddress::from_pkey(id2.pkey());
        let creator_next_addr = next_address.clone();
        let asset_hash = crypto::hash_slice(b"Test currency").to_short();

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize creator balance
        test_helpers::init_balance(
            &mut trie,
            creator_addr.clone(),
            asset_hash,
            b"10000.0",
        );

        let amount = Balance::from_bytes(b"30.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();
        let code: Vec<u8> = vec![0x32, 0x46, 0x1a, 0x35];
        let default_state: Vec<u8> = vec![0x1a, 0xff, 0x22, 0x2a];

        let mut tx = OpenContract {
            creator: id.pkey().clone(),
            next_address,
            fee: fee.clone(),
            code: code.clone(),
            default_state: default_state.clone(),
            fee_hash: asset_hash,
            amount: amount.clone(),
            asset_hash: asset_hash,
            self_payable: true,
            nonce: 3429,
            address: None,
            signature: None,
            hash: None,
        };

        tx.compute_address();
        tx.sign(id.skey().clone());
        tx.compute_hash();

        // Apply transaction
        tx.apply(&mut trie);

        let creator_nonce_key = [creator_addr.as_bytes(), &b".n"[..]].concat();
        let receiver_nonce_key = [tx.address.as_ref().unwrap().as_bytes(), &b".n"[..]].concat();
        let creator_addr_mapping_key = [creator_addr.as_bytes(), &b".am"[..]].concat();
        let creator_next_addr_mapping_key = [creator_next_addr.as_bytes(), &b".am"[..]].concat();

        let code_key = [tx.address.as_ref().unwrap().as_bytes(), &b".c"[..]].concat();
        let state_key = [tx.address.as_ref().unwrap().as_bytes(), &b".q"[..]].concat();
        let self_payable_key = [tx.address.as_ref().unwrap().as_bytes(), &b".y"[..]].concat();

        let bin_creator_nonce = &trie.get(&creator_nonce_key).unwrap().unwrap();
        let bin_receiver_nonce = &trie.get(&receiver_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let creator_balance_key = [creator_addr.as_bytes(), &b"."[..], &bin_asset_hash[..]].concat();

        let balance = Balance::from_bytes(&trie.get(&creator_balance_key).unwrap().unwrap()).unwrap();
        let written_code = trie.get(&code_key).unwrap().unwrap();
        let written_state = trie.get(&state_key).unwrap().unwrap();
        let written_self_payable = trie.get(&self_payable_key).unwrap().unwrap();

        assert_eq!(trie.get(&creator_addr_mapping_key).unwrap(), None);
        let creator_next_addr_mapping = trie.get(&creator_next_addr_mapping_key).unwrap().unwrap();

        // Check address mappings
        assert_eq!(creator_next_addr_mapping, creator_addr.as_bytes());

        // Check nonces
        assert_eq!(bin_creator_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bin_receiver_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 0]);

        // Verify that the correct amount of funds have been subtracted from the sender
        assert_eq!(
            balance,
            Balance::from_bytes(b"10000.0").unwrap() - amount.clone() - fee.clone()
        );

        // Verify shares and share map
        assert_eq!(written_code, code);
        assert_eq!(written_state, default_state);
        assert_eq!(written_self_payable, vec![1]);
    }

    quickcheck! {
        fn serialize_deserialize(tx: OpenContract) -> bool {
            tx == OpenContract::from_bytes(&OpenContract::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: OpenContract) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            code: Vec<u8>,
            default_state: Vec<u8>,
            amount: Balance,
            asset_hash: Hash,
            fee: Balance,
            fee_hash: Hash,
            self_payable: bool
        ) -> bool {
            let id = Identity::new();
            let id2 = Identity::new();

            let mut tx = OpenContract {
                creator: id.pkey().clone(),
                next_address: NormalAddress::from_pkey(id2.pkey()),
                amount: amount,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                nonce: 54432,
                fee: fee,
                self_payable: self_payable,
                default_state: default_state,
                code: code,
                address: None,
                signature: None,
                hash: None
            };

            tx.compute_address();
            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
