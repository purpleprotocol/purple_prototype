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
use transaction::*;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateMintable {
    creator: Address,
    receiver: Address,
    minter_address: Address,
    currency_hash: Hash,
    coin_supply: u64,
    max_supply: u64,
    precision: u8,
    fee_hash: Hash,
    fee: Balance,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl CreateMintable {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(9)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Precision            - 8bits
    /// 4) Coin supply          - 64bits
    /// 5) Max supply           - 64bits
    /// 6) Creator              - 32byte binary
    /// 7) Receiver             - 32byte binary
    /// 8) Minter address       - 32byte binary
    /// 9) Currency hash        - 32byte binary
    /// 10) Fee hash             - 32byte binary
    /// 11) Hash                - 32byte binary
    /// 12) Signature           - 64byte binary
    /// 13) Fee                 - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 9;

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
        let minter_address = &self.minter_address.to_bytes();
        let currency_hash = &&self.currency_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let coin_supply = &self.coin_supply;
        let max_supply = &self.max_supply;
        let precision = &self.precision;
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u8(*precision).unwrap();
        buffer.write_u64::<BigEndian>(*coin_supply).unwrap();
        buffer.write_u64::<BigEndian>(*max_supply).unwrap();

        buffer.append(&mut creator.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut minter_address.to_vec());
        buffer.append(&mut currency_hash.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature);
        buffer.append(&mut fee.to_vec());

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<CreateMintable, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let tx_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        if tx_type != 9 {
            return Err("Bad transation type");
        }

        rdr.set_position(1);

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(2);

        let precision = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad precision");
        };

        rdr.set_position(3);

        let coin_supply = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad coin supply");
        };

        rdr.set_position(11);

        let max_supply = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad max supply");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..19).collect();

        let creator = if buf.len() > 32 as usize {
            let creator_vec: Vec<u8> = buf.drain(..32).collect();
            Address::from_slice(&creator_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 32 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..32).collect();
            Address::from_slice(&receiver_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let minter_address = if buf.len() > 32 as usize {
            let minter_address_vec: Vec<u8> = buf.drain(..32).collect();
            Address::from_slice(&minter_address_vec)
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

        let signature = if buf.len() > 65 as usize {
            let sig_vec: Vec<u8> = buf.drain(..65).collect();
            
            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_)  => return Err("Bad signature")
            }
        } else {
            return Err("Incorrect packet structure");
        };

        println!("DEBUG 1 Buf len: {} Fee len: {}", buf.len(), fee_len);

        let fee = if buf.len() == fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();
            
            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad gas price")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let create_mintable = CreateMintable {
            creator: creator,
            receiver: receiver,
            coin_supply: coin_supply,
            fee_hash: fee_hash,
            minter_address: minter_address,
            max_supply: max_supply,
            fee: fee,
            precision: precision,
            currency_hash: currency_hash,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(create_mintable)
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for CreateMintable {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> CreateMintable {
        CreateMintable {
            creator: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            minter_address: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            coin_supply: Arbitrary::arbitrary(g),
            max_supply: Arbitrary::arbitrary(g),
            precision: Arbitrary::arbitrary(g),
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
        fn serialize_deserialize(tx: CreateMintable) -> bool {
            tx == CreateMintable::from_bytes(&CreateMintable::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}