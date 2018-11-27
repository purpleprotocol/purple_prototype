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

use account::{NormalAddress, ShareholdersAddress, Balance, Signature, Shares, ShareMap};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::Hash;
use serde::{Deserialize, Serialize};
use transaction::*;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OpenShares {
    creator: NormalAddress,
    shares: Shares,
    share_map: ShareMap,
    amount: Balance,
    currency_hash: Hash,
    fee: Balance,
    fee_hash: Hash,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<ShareholdersAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stock_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenShares {
    pub const TX_TYPE: u8 = 6;

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
    /// 10) Creator                 - 33byte binary
    /// 11) Address                 - 33byte binary
    /// 12) Hash                    - 32byte binary
    /// 13) Signature               - 64byte binary
    /// 14) Amount                  - Binary of amount length
    /// 15) Fee                     - Binary of fee length
    /// 16) Shares                  - Binary of shares length
    /// 17) Share map               - Binary of share map length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

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

    pub fn from_bytes(bytes: &[u8]) -> Result<OpenShares, &'static str> {
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

        let amount_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad amount len");
        };

        rdr.set_position(2);

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(3);

        let shares_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad shares len");
        };

        rdr.set_position(5);

        let share_map_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad share map len");
        };

        rdr.set_position(7);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..15).collect();

        let stock_hash = if buf.len() > 32 as usize {
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

        let currency_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let creator = if buf.len() > 33 as usize {
            let creator_vec: Vec<u8> = buf.drain(..33).collect();
            
            match NormalAddress::from_bytes(&creator_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let address = if buf.len() > 33 as usize {
            let address_vec: Vec<u8> = buf.drain(..33).collect();
            
            match ShareholdersAddress::from_bytes(&address_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
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

        let signature = if buf.len() > 65 as usize {
            let sig_vec: Vec<u8> = buf.drain(..65 as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig)   => sig,
                Err(err)  => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let amount = if buf.len() > amount_len as usize {
            let amount_vec: Vec<u8> = buf.drain(..amount_len as usize).collect();

            match Balance::from_bytes(&amount_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad amount")
            }
        } else {
            return Err("Incorrect packet structure")
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

        let shares = if buf.len() > shares_len as usize {
            let shares_vec: Vec<u8> = buf.drain(..shares_len as usize).collect();

            match Shares::from_bytes(&shares_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad shares")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let share_map = if buf.len() == share_map_len as usize {
            let share_map_vec: Vec<u8> = buf.drain(..share_map_len as usize).collect();

            match ShareMap::from_bytes(&share_map_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad share map")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let open_shares = OpenShares {
            creator: creator,
            shares: shares,
            share_map: share_map,
            currency_hash: currency_hash,
            amount: amount,
            fee_hash: fee_hash,
            fee: fee,
            nonce: nonce,
            stock_hash: Some(stock_hash),
            address: Some(address),
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(open_shares)
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenShares {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> OpenShares {
        OpenShares {
            creator: Arbitrary::arbitrary(g),
            shares: Arbitrary::arbitrary(g),
            share_map: Arbitrary::arbitrary(g),
            amount: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            address: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            stock_hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: OpenShares) -> bool {
            tx == OpenShares::from_bytes(&OpenShares::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}