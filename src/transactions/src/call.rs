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

use account::{Address, Balance, Signature};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::Hash;
use serde::{Deserialize, Serialize};
use transaction::*;
use std::io::Cursor;
use std::str;

#[derive(Serialize, Deserialize)]
pub struct Call {
    from: Address,
    to: Address,
    inputs: String, // TODO: Change to contract inputs type
    amount: Balance,
    fee: Balance,
    gas_price: Balance,
    gas_limit: u64,
    currency_hash: Hash,
    fee_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl Call {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(1)  - 8bits
    /// 2) Gas price length     - 8bits
    /// 3) Amount length        - 8bits
    /// 4) Fee length           - 8bits
    /// 5) Signature length     - 16bits
    /// 6) Inputs length        - 16bits
    /// 7) Gas limit            - 64bits
    /// 8) From                 - 32byte binary
    /// 9) To                   - 32byte binary
    /// 10) Currency hash       - 32byte binary
    /// 11) Fee hash            - 32byte binary
    /// 12) Hash                - 32byte binary
    /// 13) Signature           - Binary of signature length
    /// 14) Gas price           - Binary of gas price length
    /// 15) Amount              - Binary of amount length
    /// 16) Fee                 - Binary of fee length
    /// 17) Inputs              - Binary of inputs length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 1;

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
        let currency_hash = &&self.currency_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let amount = &self.amount.to_bytes();
        let gas_price = &self.gas_price.to_bytes();
        let gas_limit = &self.gas_limit;
        let fee = &self.fee.to_bytes();
        let inputs = &self.inputs.as_bytes();

        let gas_price_len = gas_price.len();
        let amount_len = amount.len();
        let fee_len = fee.len();
        let signature_len = signature.len();
        let inputs_len = inputs.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(gas_price_len as u8).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(inputs_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*gas_limit).unwrap();

        buffer.append(&mut from.to_vec());
        buffer.append(&mut to.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature);
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

        if tx_type != 1 {
            return Err("Bad transation type");
        }

        let gas_price_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad gas price len");
        };

        let amount_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad amount len");
        };

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
        };

        let inputs_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad inputs len");
        };

        let gas_limit = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad gas limit");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();

        let from = if buf.len() > 32 as usize {
            let from_vec = buf.split_off(31);
            Address::from_slice(&from_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let to = if buf.len() > 32 as usize {
            let to_vec = buf.split_off(31);
            Address::from_slice(&to_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let currency_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec = buf.split_off(31);

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let fee_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec = buf.split_off(31);

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec = buf.split_off(31);

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() > signature_len as usize {
            let sig_vec = buf.split_off(signature_len as usize - 1);
            
            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_)  => return Err("Bad signature")
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let gas_price = if buf.len() > gas_price_len as usize {
            let gas_price_vec = buf.split_off(gas_price_len as usize - 1);
            
            match Balance::from_bytes(&gas_price_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad gas price")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let amount = if buf.len() > amount_len as usize {
            let amount_vec = buf.split_off(amount_len as usize - 1);
            
            match Balance::from_bytes(&amount_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad amount")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let fee = if buf.len() > fee_len as usize {
            let fee_vec = buf.split_off(fee_len as usize - 1);
            
            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad gas price")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let inputs = if buf.len() == inputs_len as usize {
            // TODO: Deserialize contract inputs
            match str::from_utf8(&buf) {
                Ok(result) => result,
                Err(_)     => return Err("Bad inputs")
            }
        } else {
            return Err("Incorrect packet structure")
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
            currency_hash: currency_hash,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(call)
    }
}