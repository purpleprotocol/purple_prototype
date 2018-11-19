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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Send {
    from: Address,
    to: Address,
    amount: Balance,
    fee: Balance,
    currency_hash: Hash,
    fee_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl Send {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(3)      - 8bits
    /// 2) Amount length            - 8bits
    /// 3) Fee length               - 8bits
    /// 4) Signature length         - 16bits
    /// 5) From                     - 32byte binary
    /// 6) To                       - 32byte binary
    /// 7) Currency hash            - 32byte binary
    /// 8) Fee hash                 - 32byte binary
    /// 9) Hash                     - 32byte binary
    /// 10) Signature               - Binary of signature length
    /// 11) Amount                  - Binary of amount length
    /// 12) Fee                     - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 3;

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

        let from = &self.from.to_bytes();
        let to = &self.to.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let currency_hash = &&self.currency_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();
        let amount_len = amount.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();

        buffer.append(&mut from.to_vec());
        buffer.append(&mut to.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());

        Ok(buffer)
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for Send {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Send {
        Send {
            from: Arbitrary::arbitrary(g),
            to: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}
