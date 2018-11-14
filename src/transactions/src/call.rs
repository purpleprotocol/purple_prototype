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
use causality::Stamp;
use crypto::Hash;
use serde::{Deserialize, Serialize};
use transaction::*;

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
}