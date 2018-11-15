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

use account::{Address, Balance, Signature, Shares, ShareMap};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::Hash;
use serde::{Deserialize, Serialize};
use transaction::*;

#[derive(Serialize, Deserialize)]
pub struct OpenShares {
    creator: Address,
    shares: Shares,
    share_map: ShareMap,
    amount: Balance,
    currency_hash: Hash,
    fee: Balance,
    fee_hash: Hash,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stock_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenShares {
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
    /// 10) Creator                 - 32byte binary
    /// 11) Address                 - 32byte binary
    /// 12) Hash                    - 32byte binary
    /// 13) Signature               - 64byte binary
    /// 14) Amount                  - Binary of amount length
    /// 15) Fee                     - Binary of fee length
    /// 16) Shares                  - Binary of shares length
    /// 17) Share map               - Binary of share map length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 6;

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
}
