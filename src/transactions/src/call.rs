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
use purple_vm::Gas;
use std::io::Cursor;
use std::str;

#[derive(Debug, PartialEq, Clone)]
pub struct Call {
    pub(crate) from: Pk,
    pub(crate) next_address: NormalAddress,
    pub(crate) to: ContractAddress,
    pub(crate) inputs: String, // TODO: Change to contract inputs type
    pub(crate) amount: Balance,
    pub(crate) fee: Balance,
    pub(crate) gas_price: Balance,
    pub(crate) gas_limit: Gas,
    pub(crate) asset_hash: ShortHash,
    pub(crate) fee_hash: ShortHash,
    pub(crate) nonce: u64,
    pub(crate) hash: Option<Hash>,
    pub(crate) signature: Option<Signature>,
}

impl Call {
    pub const TX_TYPE: u8 = 1;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<BlakeDbHasher, Codec>) -> bool {
        unimplemented!();
    }

    pub fn apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) {
        unimplemented!();
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
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.from),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(1)  - 8bits
    /// 2) Gas limit length     - 8bits
    /// 3) Gas price length     - 8bits
    /// 4) Amount length        - 8bits
    /// 5) Fee length           - 8bits
    /// 6) Inputs length        - 16bits
    /// 7) Nonce                - 64bits
    /// 8) Currency flag        - 1byte (Value is 1 if currency and fee hashes are identical. Otherwise is 0)
    /// 9) Currency hash        - 8byte binary
    /// 10) Fee hash            - 8byte binary (Non-existent if currency flag is true)
    /// 11) From                - 33byte binary
    /// 12) To                  - 33byte binary
    /// 13) Next address        - 33byte binary
    /// 14) Signature           - 64byte binary
    /// 14) Gas price           - Binary of gas price length
    /// 16) Amount              - Binary of amount length
    /// 17) Fee                 - Binary of fee length
    /// 18) Inputs              - Binary of inputs length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let mut signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let from = &self.from.0;
        let to = self.to.to_bytes();
        let next_address = self.next_address.to_bytes();
        let asset_hash = &self.asset_hash.0;
        let fee_hash = &self.fee_hash.0;
        let amount = self.amount.to_bytes();
        let gas_price = self.gas_price.to_bytes();
        let gas_limit = self.gas_limit.to_bytes();
        let fee = self.fee.to_bytes();
        let inputs = self.inputs.as_bytes();
        let nonce = &self.nonce;
        let currency_flag = if asset_hash == fee_hash {
            1
        } else {
            0
        };

        let gas_limit_len = gas_limit.len();
        let gas_price_len = gas_price.len();
        let amount_len = amount.len();
        let fee_len = fee.len();
        let signature_len = signature.len();
        let inputs_len = inputs.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(gas_limit_len as u8).unwrap();
        buffer.write_u8(gas_price_len as u8).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(inputs_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();
        buffer.write_u8(currency_flag);
        buffer.extend_from_slice(asset_hash);

        if currency_flag == 0 {
            buffer.extend_from_slice(fee_hash);
        }

        buffer.extend_from_slice(&self.from.0);
        buffer.extend_from_slice(&to);
        buffer.extend_from_slice(&next_address);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(&gas_limit);
        buffer.extend_from_slice(&gas_price);
        buffer.extend_from_slice(&amount);
        buffer.extend_from_slice(&fee);
        buffer.extend_from_slice(inputs);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Call, &'static str> {
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

        let gas_limit_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad gas limit len");
        };

        rdr.set_position(2);

        let gas_price_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad gas price len");
        };

        rdr.set_position(3);

        let amount_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad amount len");
        };

        rdr.set_position(4);

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(5);

        let inputs_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad inputs len");
        };

        rdr.set_position(7);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        rdr.set_position(8);

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
        let mut buf = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..16).collect();

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

        let from = if buf.len() > 32 as usize {
            let from_vec: Vec<u8> = buf.drain(..32).collect();
            let mut from = [0; 32];
            from.copy_from_slice(&from_vec);

            Pk(from)
        } else {
            return Err("Incorrect packet structure");
        };

        let to = if buf.len() > 33 as usize {
            let to_vec: Vec<u8> = buf.drain(..33).collect();

            match ContractAddress::from_bytes(&to_vec) {
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
            let sig_vec: Vec<u8> = buf.drain(..64 as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_) => return Err("Bad signature"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let gas_limit = if buf.len() > gas_limit_len as usize {
            let gas_limit_vec: Vec<u8> = buf.drain(..gas_limit_len as usize).collect();

            match Gas::from_bytes(&gas_limit_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad gas limit"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let gas_price = if buf.len() > gas_price_len as usize {
            let gas_price_vec: Vec<u8> = buf.drain(..gas_price_len as usize).collect();

            match Balance::from_bytes(&gas_price_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad gas price"),
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

        let fee = if buf.len() >= fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad gas price"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let inputs = if buf.len() == inputs_len as usize {
            // TODO: Deserialize contract inputs
            match str::from_utf8(&buf) {
                Ok(result) => result,
                Err(_) => return Err("Bad inputs"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let mut call = Call {
            from,
            next_address,
            to,
            fee_hash,
            fee,
            amount,
            gas_limit,
            inputs: inputs.to_string(),
            gas_price,
            asset_hash,
            nonce,
            hash: None,
            signature: Some(signature),
        };

        call.compute_hash();
        Ok(call)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Call {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &Call) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let to = obj.to.to_bytes();
    let next_address = obj.next_address.to_bytes();
    let amount = obj.amount.to_bytes();
    let fee = obj.fee.to_bytes();
    let gas_limit = obj.gas_limit.to_bytes();
    let gas_price = obj.gas_price.to_bytes();
    let inputs = obj.inputs.as_bytes();
    let asset_hash = &obj.asset_hash.0;
    let fee_hash = &obj.fee_hash.0;

    buf.write_u64::<BigEndian>(obj.nonce).unwrap();
    buf.extend_from_slice(&obj.from.0);
    buf.extend_from_slice(&to);
    buf.extend_from_slice(&next_address);
    buf.extend_from_slice(asset_hash);
    buf.extend_from_slice(fee_hash);
    buf.extend_from_slice(&amount);
    buf.extend_from_slice(&fee);
    buf.extend_from_slice(&gas_limit);
    buf.extend_from_slice(&gas_price);
    buf.extend_from_slice(&inputs);
    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Call {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Call {
        let (pk, _) = crypto::gen_keypair();
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);

        let asset_hash = Arbitrary::arbitrary(g);
        let fee_hash = if random == 1 {
            asset_hash
        } else {
            Arbitrary::arbitrary(g)
        };

        let mut tx = Call {
            from: pk,
            next_address: Arbitrary::arbitrary(g),
            to: Arbitrary::arbitrary(g),
            fee_hash,
            fee: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            gas_limit: Arbitrary::arbitrary(g),
            inputs: Arbitrary::arbitrary(g),
            gas_price: Arbitrary::arbitrary(g),
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
    use super::*;
    use account::NormalAddress;
    use crypto::Identity;

    quickcheck! {
        fn serialize_deserialize(tx: Call) -> bool {
            tx == Call::from_bytes(&Call::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: Call) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            to: ContractAddress,
            amount: Balance,
            fee: Balance,
            inputs: String,
            gas_price: Balance,
            gas_limit: Gas,
            asset_hash: ShortHash,
            fee_hash: ShortHash
        ) -> bool {
            let id = Identity::new();
            let id2 = Identity::new();
            let next_address = NormalAddress::from_pkey(id2.pkey());

            let mut tx = Call {
                from: id.pkey().clone(),
                next_address,
                to: to,
                amount: amount,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                gas_price: gas_price,
                gas_limit: gas_limit,
                inputs: inputs,
                nonce: 1,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
