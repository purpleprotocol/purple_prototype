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

use account::{Address, NormalAddress, Balance, ContractAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Signature, Hash, PublicKey as Pk, SecretKey as Sk};
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use std::io::Cursor;
use std::str;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OpenContract {
    owner: NormalAddress,
    code: Vec<u8>,
    default_state: Vec<u8>,
    amount: Balance,
    asset_hash: Hash,
    fee: Balance,
    fee_hash: Hash,
    self_payable: bool,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<ContractAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenContract {
    pub const TX_TYPE: u8 = 2;

    /// Applies the open contract transaction to the provided database.
    ///
    /// This function will panic if the `owner` account does not exist
    /// or if the account address already exists in the ledger.
    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        let bin_owner = &self.owner.to_bytes();
        let bin_address = &self.address.clone().unwrap().to_bytes();
        let bin_currency_hash = &self.asset_hash.to_vec();
        let bin_fee_hash = &self.fee_hash.to_vec();
        let self_payable: Vec<u8> = if self.self_payable { vec![1] } else { vec![0] };

        let code = &self.code;
        let default_state = &self.default_state;

        // Convert addresses to strings
        let owner = hex::encode(bin_owner);
        let address = hex::encode(bin_address);

        // Convert hashes to strings
        let asset_hash = hex::encode(bin_currency_hash);
        let fee_hash = hex::encode(bin_fee_hash);

        // Calculate nonce keys
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let owner_nonce_key = format!("{}.n", owner);
        let address_nonce_key = format!("{}.n", address);
        let owner_nonce_key = owner_nonce_key.as_bytes();
        let address_nonce_key = address_nonce_key.as_bytes();

        if let Ok(Some(_)) = trie.get(&address_nonce_key) {
            panic!("The created address already exists in the ledger!");
        }

        // Calculate code key
        //
        // The key of a contract's code has the following format:
        // `<contract-address>.c`
        let code_key = format!("{}.c", address);
        let code_key = code_key.as_bytes();

        // Calculate state key
        //
        // The key of a contract's state has the following format:
        // `<contract-address>.q`
        let state_key = format!("{}.q", address);
        let state_key = state_key.as_bytes();

        // Calculate self payable key
        //
        // The key of a contract's self payable entry has the following format:
        // `<contract-address>.y`
        let self_payable_key = format!("{}.y", address);
        let self_payable_key = self_payable_key.as_bytes();

        // Retrieve serialized nonce
        let bin_owner_nonce = &trie.get(&owner_nonce_key).unwrap().unwrap();

        let mut nonce_rdr = Cursor::new(bin_owner_nonce);

        // Read the nonce of the owner
        let mut nonce = nonce_rdr.read_u64::<BigEndian>().unwrap();

        // Increment owner nonce
        nonce += 1;

        let mut nonce_buf: Vec<u8> = Vec::with_capacity(8);

        // Write new nonce to buffer
        nonce_buf.write_u64::<BigEndian>(nonce).unwrap();

        // Calculate currency keys
        //
        // The key of a currency entry has the following format:
        // `<account-address>.<currency-hash>`
        let owner_cur_key = format!("{}.{}", owner, asset_hash);
        let owner_fee_key = format!("{}.{}", owner, fee_hash);
        let address_cur_key = format!("{}.{}", address, asset_hash);

        if fee_hash == asset_hash {
            // The transaction's fee is paid in the same currency
            // that is being transferred, so we only retrieve one
            // balance.
            let mut owner_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&owner_cur_key.as_bytes()).unwrap(),
                    "The owner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from owner balance
            owner_balance -= self.fee.clone();

            // Subtract amount transferred from owner balance
            owner_balance -= self.amount.clone();

            let receiver_balance = self.amount.clone();

            // Update trie
            trie.insert(self_payable_key, &self_payable).unwrap();
            trie.insert(state_key, default_state).unwrap();
            trie.insert(code_key, code).unwrap();
            trie.insert(owner_cur_key.as_bytes(), &owner_balance.to_bytes())
                .unwrap();
            trie.insert(address_cur_key.as_bytes(), &receiver_balance.to_bytes())
                .unwrap();
            trie.insert(owner_nonce_key, &nonce_buf).unwrap();
            trie.insert(address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
        } else {
            // The transaction's fee is paid in a different currency
            // than the one being transferred so we retrieve both balances.
            let mut owner_cur_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&owner_cur_key.as_bytes()).unwrap(),
                    "The owner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            let mut owner_fee_balance = unwrap!(
                Balance::from_bytes(&unwrap!(
                    trie.get(&owner_fee_key.as_bytes()).unwrap(),
                    "The owner does not have an entry for the given currency"
                )),
                "Invalid stored balance format"
            );

            // Subtract fee from owner
            owner_fee_balance -= self.fee.clone();

            // Subtract amount transferred from owner
            owner_cur_balance -= self.amount.clone();

            let receiver_balance = self.amount.clone();

            // Update trie
            trie.insert(self_payable_key, &self_payable).unwrap();
            trie.insert(state_key, default_state).unwrap();
            trie.insert(code_key, code).unwrap();
            trie.insert(owner_cur_key.as_bytes(), &owner_cur_balance.to_bytes())
                .unwrap();
            trie.insert(owner_fee_key.as_bytes(), &owner_fee_balance.to_bytes())
                .unwrap();
            trie.insert(address_cur_key.as_bytes(), &receiver_balance.to_bytes())
                .unwrap();
            trie.insert(owner_nonce_key, &nonce_buf).unwrap();
            trie.insert(address_nonce_key, &[0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
        }
    }

    /// Computes the address of the opened contract.
    ///
    /// A contract's address is computed by appending the owner's
    /// address together with the code and the default state to
    /// the owner's nonce. The address is the hash of the result.
    pub fn compute_address(&mut self) {
        let mut buf: Vec<u8> = Vec::new();

        let owner = &self.owner.to_bytes();
        let code = &self.code;
        let state = &self.default_state;
        let nonce = &self.nonce;

        buf.write_u64::<BigEndian>(*nonce).unwrap();
        buf.append(&mut owner.to_vec());
        buf.append(&mut code.to_vec());
        buf.append(&mut state.to_vec());

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
            Some(ref sig) => crypto::verify(&message, sig, &self.owner.pkey()),
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
    /// 8) Owner                    - 33byte binary
    /// 9) Address                  - 33byte binary
    /// 10) Currency hash           - 32byte binary
    /// 11) Fee hash                - 32byte binary
    /// 12) Hash                    - 32byte binary
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

        let self_payable: u8 = if self.self_payable { 1 } else { 0 };
        let owner = &self.owner.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let code = &self.code;
        let default_state = &self.default_state;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();
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

        buffer.append(&mut owner.to_vec());
        buffer.append(&mut address.to_vec());
        buffer.append(&mut asset_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut default_state.to_vec());
        buffer.append(&mut code.to_vec());

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

        let owner = if buf.len() > 33 as usize {
            let owner_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&owner_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the owner field");
        };

        let address = if buf.len() > 33 as usize {
            let address_vec: Vec<u8> = buf.drain(..33).collect();

            match ContractAddress::from_bytes(&address_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the owner field");
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

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the hash field");
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

        let open_contract = OpenContract {
            owner: owner,
            amount: amount,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            fee: fee,
            default_state: default_state,
            self_payable: self_payable,
            nonce: nonce,
            code: code,
            address: Some(address),
            hash: Some(hash),
            signature: Some(signature),
        };

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
    let mut owner = obj.owner.to_bytes();
    let self_payable: u8 = if obj.self_payable { 1 } else { 0 };
    let fee_hash = &obj.fee_hash.0;
    let code = &obj.code;
    let default_state = &obj.default_state;
    let mut fee = obj.fee.to_bytes();

    buf.write_u8(self_payable).unwrap();

    // Compose data to hash
    buf.append(&mut owner);
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut code.to_vec());
    buf.append(&mut default_state.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenContract {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> OpenContract {
        OpenContract {
            owner: Arbitrary::arbitrary(g),
            code: Arbitrary::arbitrary(g),
            default_state: Arbitrary::arbitrary(g),
            self_payable: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
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
    use account::NormalAddress;
    use crypto::Identity;

    #[test]
    fn apply_it_opens_a_contract() {
        let id = Identity::new();
        let owner_addr = NormalAddress::from_pkey(*id.pkey());
        let asset_hash = crypto::hash_slice(b"Test currency");

        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        // Manually initialize owner balance
        test_helpers::init_balance(
            &mut trie,
            Address::Normal(owner_addr.clone()),
            asset_hash,
            b"10000.0",
        );

        let amount = Balance::from_bytes(b"30.0").unwrap();
        let fee = Balance::from_bytes(b"10.0").unwrap();
        let code: Vec<u8> = vec![0x32, 0x46, 0x1a, 0x35];
        let default_state: Vec<u8> = vec![0x1a, 0xff, 0x22, 0x2a];

        let mut tx = OpenContract {
            owner: owner_addr,
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
        tx.hash();

        // Apply transaction
        tx.apply(&mut trie);

        // Commit changes
        trie.commit();

        let owner_nonce_key = format!("{}.n", hex::encode(&owner_addr.to_bytes()));
        let owner_nonce_key = owner_nonce_key.as_bytes();
        let receiver_nonce_key =
            format!("{}.n", hex::encode(tx.address.clone().unwrap().to_bytes()));
        let receiver_nonce_key = receiver_nonce_key.as_bytes();

        let code_key = format!("{}.c", hex::encode(tx.address.clone().unwrap().to_bytes()));
        let code_key = code_key.as_bytes();
        let state_key = format!("{}.q", hex::encode(tx.address.clone().unwrap().to_bytes()));
        let state_key = state_key.as_bytes();
        let self_payable_key = format!("{}.y", hex::encode(tx.address.unwrap().to_bytes()));
        let self_payable_key = self_payable_key.as_bytes();

        let bin_owner_nonce = &trie.get(&owner_nonce_key).unwrap().unwrap();
        let bin_receiver_nonce = &trie.get(&receiver_nonce_key).unwrap().unwrap();

        let bin_asset_hash = asset_hash.to_vec();
        let hex_asset_hash = hex::encode(&bin_asset_hash);

        let owner_balance_key =
            format!("{}.{}", hex::encode(&owner_addr.to_bytes()), hex_asset_hash);
        let owner_balance_key = owner_balance_key.as_bytes();

        let balance = Balance::from_bytes(&trie.get(&owner_balance_key).unwrap().unwrap()).unwrap();
        let written_code = trie.get(&code_key).unwrap().unwrap();
        let written_state = trie.get(&state_key).unwrap().unwrap();
        let written_self_payable = trie.get(&self_payable_key).unwrap().unwrap();

        // Check nonces
        assert_eq!(bin_owner_nonce.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
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
                tx.hash();
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

            let mut tx = OpenContract {
                owner: NormalAddress::from_pkey(*id.pkey()),
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
