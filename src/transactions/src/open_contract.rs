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
pub struct OpenContract {
    owner: Address,
    code: String,
    default_state: String,
    fee: Balance,
    fee_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenContract {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(2)      - 8bits
    /// 2) Fee length               - 8bits
    /// 3) State length             - 16bits
    /// 4) Code length              - 16bits
    /// 5) Owner                    - 32byte binary
    /// 6) Fee hash                 - 32byte binary
    /// 8) Hash                     - 32byte binary
    /// 9) Signature                - 64byte binary
    /// 10) Fee                     - Binary of fee length
    /// 11) Default state           - Binary of state length
    /// 12) Code                    - Binary of code length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 2;

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

        let owner = &self.owner.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let code = &self.code.as_bytes();
        let default_state = &self.default_state.as_bytes();
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();
        let code_len = code.len();
        let state_len = default_state.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(state_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(code_len as u16).unwrap();

        buffer.append(&mut owner.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut default_state.to_vec());
        buffer.append(&mut code.to_vec());

        Ok(buffer)
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenContract {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> OpenContract {
        OpenContract {
            owner: Arbitrary::arbitrary(g),
            code: Arbitrary::arbitrary(g),
            default_state: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}
