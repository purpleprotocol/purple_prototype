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
use crypto::{Hash, PublicKey as Pk, SecretKey as Sk, Signature};
use purple_vm::Gas;
use std::io::Cursor;
use std::str;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Call {
    pub(crate) from: NormalAddress,
    pub(crate) to: ContractAddress,
    pub(crate) inputs: String, // TODO: Change to contract inputs type
    pub(crate) amount: Balance,
    pub(crate) fee: Balance,
    pub(crate) gas_price: Balance,
    pub(crate) gas_limit: Gas,
    pub(crate) asset_hash: Hash,
    pub(crate) fee_hash: Hash,
    pub(crate) nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature: Option<Signature>,
}

impl Call {
    pub const TX_TYPE: u8 = 1;

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
            Some(ref sig) => crypto::verify(&message, sig, &self.from.pkey()),
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
    /// 8) From                 - 33byte binary
    /// 9) To                   - 33byte binary
    /// 10) Currency hash       - 32byte binary
    /// 11) Fee hash            - 32byte binary
    /// 12) Hash                - 32byte binary
    /// 13) Signature           - 64byte binary
    /// 14) Gas price           - Binary of gas price length
    /// 15) Amount              - Binary of amount length
    /// 16) Fee                 - Binary of fee length
    /// 17) Inputs              - Binary of inputs length
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

        let from = &self.from.to_bytes();
        let to = &self.to.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let amount = &self.amount.to_bytes();
        let gas_price = &self.gas_price.to_bytes();
        let gas_limit = &self.gas_limit.to_bytes();
        let fee = &self.fee.to_bytes();
        let inputs = &self.inputs.as_bytes();
        let nonce = &self.nonce;

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

        buffer.append(&mut from.to_vec());
        buffer.append(&mut to.to_vec());
        buffer.append(&mut asset_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature);
        buffer.append(&mut gas_limit.to_vec());
        buffer.append(&mut gas_price.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut inputs.to_vec());

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

        // Consume cursor
        let mut buf = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..15).collect();

        let from = if buf.len() > 33 as usize {
            let from_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&from_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
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

        let call = Call {
            from: from,
            to: to,
            fee_hash: fee_hash,
            fee: fee,
            amount: amount,
            gas_limit: gas_limit,
            inputs: inputs.to_string(),
            gas_price: gas_price,
            asset_hash: asset_hash,
            nonce: nonce,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(call)
    }

    impl_hash!();
}

fn assemble_message(obj: &Call) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut from = obj.from.to_bytes();
    let mut to = obj.to.to_bytes();
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let mut gas_limit = obj.gas_limit.to_bytes();
    let mut gas_price = obj.gas_price.to_bytes();
    let inputs = obj.inputs.as_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to sign
    buf.append(&mut from);
    buf.append(&mut to);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut gas_limit);
    buf.append(&mut gas_price);
    buf.append(&mut inputs.to_vec());

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Call {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Call {
        Call {
            from: Arbitrary::arbitrary(g),
            to: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            gas_limit: Arbitrary::arbitrary(g),
            inputs: Arbitrary::arbitrary(g),
            gas_price: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
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
                tx.hash();
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
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();

            let mut tx = Call {
                from: NormalAddress::from_pkey(*id.pkey()),
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
