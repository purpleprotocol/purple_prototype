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

use account::{Address, Balance, MultiSig};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::Hash;
use serde::{Deserialize, Serialize};
use transaction::*;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IssueShares {
    issuer: Address,
    receiver: Address,
    shares: u64,
    fee_hash: Hash,
    fee: Balance,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<MultiSig>,
}

impl IssueShares {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(7)      - 8bits
    /// 2) Fee length               - 8bits
    /// 3) Signature length         - 16bits
    /// 4) Amount of issued shares  - 64bits
    /// 5) Issuer                   - 32byte binary
    /// 6) Receiver                 - 32byte binary
    /// 7) Fee hash                 - 32byte binary
    /// 8) Hash                     - 32byte binary
    /// 9) Fee                      - Binary of fee length
    /// 10) Signature               - Binary of signature length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 7;

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

        let issuer = &self.issuer.to_bytes();
        let receiver = &self.receiver.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let shares = &self.shares;
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*shares).unwrap();

        buffer.append(&mut issuer.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut signature);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<IssueShares, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let tx_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        if tx_type != 7 {
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

        let shares = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad shares");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..12).collect();

        let issuer = if buf.len() > 32 as usize {
            let issuer_vec: Vec<u8> = buf.drain(..32).collect();
            Address::from_slice(&issuer_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 32 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..32).collect();
            Address::from_slice(&receiver_vec)
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

        let fee = if buf.len() > fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad fee")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let signature = if buf.len() == signature_len as usize {
            let sig_vec: Vec<u8> = buf.drain(..signature_len as usize).collect();

            match MultiSig::from_bytes(&sig_vec) {
                Ok(sig)   => sig,
                Err(err)  => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let issue_shares = IssueShares {
            issuer: issuer,
            receiver: receiver,
            shares: shares,
            fee_hash: fee_hash,
            fee: fee,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(issue_shares)
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for IssueShares {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> IssueShares {
        IssueShares {
            issuer: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            shares: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: IssueShares) -> bool {
            tx == IssueShares::from_bytes(&IssueShares::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}