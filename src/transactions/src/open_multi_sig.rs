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
pub struct OpenMultiSig {
    creator: Address,
    keys: Vec<Address>,
    required_keys: u8,
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
    signature: Option<Signature>,
}

impl OpenMultiSig {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(5)      - 8bits
    /// 2) Required keys            - 8bits
    /// 3) Amount length            - 8bits
    /// 4) Fee length               - 8bits
    /// 5) Keys length              - 16bits
    /// 6) Nonce                    - 64bits
    /// 7) Fee hash                 - 32byte binary
    /// 8) Currency hash            - 32byte binary
    /// 9) Creator                  - 32byte binary
    /// 10) Address                 - 32byte binary
    /// 11) Hash                    - 32byte binary
    /// 12) Signature               - 64byte binary
    /// 13) Amount                  - Binary of amount length
    /// 14) Fee                     - Binary of fee length
    /// 15) Keys                    - Binary of keys length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 5;

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

        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(self.keys.len());
        
        for k in self.keys.iter() {
            keys.push(k.to_bytes());
        }

        // Encode keys
        let mut keys: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&keys);

        let creator = &self.creator.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let currency_hash = &&self.currency_hash.0;
        let amount = &self.amount.to_bytes();
        let fee = &self.fee.to_bytes();
        let nonce = &self.nonce;
        let required_keys = &self.required_keys;

        let fee_len = fee.len();
        let amount_len = amount.len();
        let keys_len = keys.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(*required_keys).unwrap();
        buffer.write_u8(amount_len as u8).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(keys_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut creator.to_vec());
        buffer.append(&mut address.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut amount.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut keys);

        Ok(buffer)
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenMultiSig {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> OpenMultiSig {
        OpenMultiSig {
            creator: Arbitrary::arbitrary(g),
            keys: Arbitrary::arbitrary(g),
            required_keys: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            address: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}