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

use account::{Address, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, Signature};
use serde::{Deserialize, Serialize};
use account::SigExtern;
use transaction::*;

#[derive(Serialize, Deserialize)]
pub struct CreateCurrency {
    creator: Address,
    receiver: Address,
    currency_hash: Hash,
    coin_supply: u64,
    precision: u8,
    fee_hash: Hash,
    fee: Balance,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl CreateCurrency {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(8)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Coin supply          - 64bits
    /// 4) Creator              - 32byte binary
    /// 5) Receiver             - 32byte binary
    /// 6) Currency hash        - 32byte binary
    /// 7) Fee hash             - 32byte binary
    /// 8) Hash                 - 32byte binary
    /// 9) Signature            - 64byte binary
    /// 10) Fee                 - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 8;

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

        let creator = &self.creator.to_bytes();
        let receiver = &self.receiver.to_bytes();
        let currency_hash = &&self.currency_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let coin_supply = &self.coin_supply;
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u64::<BigEndian>(*coin_supply).unwrap();

        buffer.append(&mut creator.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature);
        buffer.append(&mut fee.to_vec());

        Ok(buffer)
    }
}