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

use account::{Address, NormalAddress, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, Signature, SecretKey as Sk};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateCurrency {
    creator: NormalAddress,
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
    pub const TX_TYPE: u8 = 8;

    /// Signs the transaction with the given secret key.
    ///
    /// This function will panic if there already exists
    /// a signature and the address type doesn't match
    /// the signature type.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => { 
                crypto::verify(&message, sig.clone(), self.creator.pkey())
            },
            None => {
                false
            }
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(8)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Precision            - 8bits
    /// 4) Coin supply          - 64bits
    /// 5) Creator              - 33byte binary
    /// 6) Receiver             - 33byte binary
    /// 7) Currency hash        - 32byte binary
    /// 8) Fee hash             - 32byte binary
    /// 9) Hash                 - 32byte binary
    /// 10) Signature           - 65byte binary
    /// 11) Fee                 - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

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
        let precision = &self.precision;
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u8(*precision).unwrap();
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

    pub fn from_bytes(bytes: &[u8]) -> Result<CreateCurrency, &'static str> {
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

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..11).collect();

        let creator = if buf.len() > 33 as usize {
            let creator_vec: Vec<u8> = buf.drain(..33).collect();
            
            match NormalAddress::from_bytes(&creator_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 33 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..33).collect();
            
            match Address::from_bytes(&receiver_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
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

        let fee = if buf.len() == fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();
            
            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad gas price")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let create_currency = CreateCurrency {
            creator: creator,
            receiver: receiver,
            coin_supply: coin_supply,
            fee_hash: fee_hash,
            fee: fee,
            precision: precision,
            currency_hash: currency_hash,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(create_currency)
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &CreateCurrency) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let coin_supply = obj.coin_supply;
    let precision = obj.precision;
    let currency_hash = obj.currency_hash.0;
    let fee_hash = obj.fee_hash.0;

    buf.write_u8(precision).unwrap();
    buf.write_u64::<BigEndian>(coin_supply).unwrap();

    // Compose data to hash
    buf.append(&mut creator);
    buf.append(&mut receiver);
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &CreateCurrency) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let precision = obj.precision;
    let coin_supply = obj.coin_supply;
    let currency_hash = obj.currency_hash.0;
    let fee_hash = obj.fee_hash.0;

    buf.write_u8(precision).unwrap();
    buf.write_u64::<BigEndian>(coin_supply).unwrap();

    // Compose data to sign
    buf.append(&mut creator);
    buf.append(&mut receiver);
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for CreateCurrency {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> CreateCurrency {
        CreateCurrency {
            creator: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            currency_hash: Arbitrary::arbitrary(g),
            coin_supply: Arbitrary::arbitrary(g),
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
    use crypto::Identity;

    quickcheck! {
        fn serialize_deserialize(tx: CreateCurrency) -> bool {
            tx == CreateCurrency::from_bytes(&CreateCurrency::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: CreateCurrency) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            receiver: Address,
            fee: Balance, 
            coin_supply: u64,
            precision: u8,
            currency_hash: Hash, 
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();

            let mut tx = CreateCurrency {
                creator: NormalAddress::from_pkey(*id.pkey()),
                receiver: receiver,
                coin_supply: coin_supply,
                precision: precision,
                fee: fee,
                currency_hash: currency_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}