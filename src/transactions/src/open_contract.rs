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
use std::str;
use std::io::Cursor;

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
    pub const TX_TYPE: u8 = 2;

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(2)      - 8bits
    /// 2) Fee length               - 8bits
    /// 3) Signature length         - 16bits
    /// 4) State length             - 16bits
    /// 5) Code length              - 16bits
    /// 6) Owner                    - 33byte binary
    /// 7) Fee hash                 - 32byte binary
    /// 8) Hash                     - 32byte binary
    /// 9) Signature                - Binary of signature length
    /// 10) Fee                     - Binary of fee length
    /// 11) Default state           - Binary of state length
    /// 12) Code                    - Binary of code length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

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
        let signature_len = signature.len();
        let state_len = default_state.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();
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

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(2);

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
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

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..8).collect();

        let owner = if buf.len() > 33 as usize {
            let owner_vec: Vec<u8> = buf.drain(..33).collect();
            
            match Address::from_bytes(&owner_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the owner field");
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

        let signature = if buf.len() > signature_len as usize {
            let sig_vec: Vec<u8> = buf.drain(..signature_len as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig)   => sig,
                Err(err)  => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size of the signature field");
        };

        let fee = if buf.len() >= fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad fee")
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the fee field")
        };

        let default_state = if buf.len() >= state_len as usize {
            let state_vec: Vec<u8> = buf.drain(..state_len as usize).collect();

            match str::from_utf8(&state_vec) {
                Ok(result) => result.to_owned(),
                Err(_)     => return Err("Bad state")
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the default state field")
        };

        let code = if buf.len() == code_len as usize {
            let code_vec: Vec<u8> = buf.drain(..code_len as usize).collect();

            match str::from_utf8(&code_vec) {
                Ok(result) => result.to_owned(),
                Err(_)     => return Err("Bad code")
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is not equal with the size for the code field")
        };

        let open_contract = OpenContract {
            owner: owner,
            fee_hash: fee_hash,
            fee: fee,
            default_state: default_state,
            code: code,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(open_contract)
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

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: OpenContract) -> bool {
            tx == OpenContract::from_bytes(&OpenContract::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}