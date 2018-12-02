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

use account::{NormalAddress, MultiSigAddress, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Signature, Hash, SecretKey as Sk};
use serde::{Deserialize, Serialize};
use transaction::*;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OpenMultiSig {
    creator: NormalAddress,
    keys: Vec<NormalAddress>,
    required_keys: u8,
    amount: Balance,
    currency_hash: Hash,
    fee: Balance,
    fee_hash: Hash,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<MultiSigAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenMultiSig {
    pub const TX_TYPE: u8 = 5;

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
    /// 1) Transaction type(5)      - 8bits
    /// 2) Required keys            - 8bits
    /// 3) Amount length            - 8bits
    /// 4) Fee length               - 8bits
    /// 5) Keys length              - 16bits
    /// 6) Nonce                    - 64bits
    /// 7) Fee hash                 - 32byte binary
    /// 8) Currency hash            - 32byte binary
    /// 9) Creator                  - 33byte binary
    /// 10) Address                 - 33byte binary
    /// 11) Hash                    - 32bytse binary
    /// 12) Signature               - 64byte binary
    /// 13) Amount                  - Binary of amount length
    /// 14) Fee                     - Binary of fee length
    /// 15) Keys                    - Binary of keys length
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

    pub fn from_bytes(bytes: &[u8]) -> Result<OpenMultiSig, &'static str> {
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

        let required_keys = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad required keys");
        };

        rdr.set_position(2);

        let amount_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad amount len");
        };

        rdr.set_position(3);

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(4);

        let keys_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad keys len");
        };

        rdr.set_position(6);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..14).collect();

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
            
            match MultiSigAddress::from_bytes(&address_vec) {
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

        let keys = if buf.len() == keys_len as usize {
            let keys_vec: Vec<u8> = buf.drain(..keys_len as usize).collect();
            let deserialized_keys: Vec<Vec<u8>> = rlp::decode_list(&keys_vec);
            let mut keys: Vec<NormalAddress> = Vec::with_capacity(keys_len as usize);

            for k in deserialized_keys {
                match NormalAddress::from_bytes(&k) {
                    Ok(addr) => keys.push(addr),
                    Err(err) => return Err(err)
                }
            }

            keys
        } else {
            return Err("Incorrect packet structure")
        };

        let open_multi_sig = OpenMultiSig {
            creator: creator,
            required_keys: required_keys,
            keys: keys,
            currency_hash: currency_hash,
            amount: amount,
            fee_hash: fee_hash,
            fee: fee,
            nonce: nonce,
            address: Some(address),
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(open_multi_sig)
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &OpenMultiSig) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut address = if let Some(ref address) = obj.address {
        address.to_bytes()
    } else {
        panic!("Address field is missing");
    };

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(obj.keys.len());
        
    for k in obj.keys.iter() {
        keys.push(k.to_bytes());
    }

    // Encode keys
    let mut keys: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&keys);

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let currency_hash = &obj.currency_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let nonce = obj.nonce;
    let required_keys = obj.required_keys;

    buf.write_u8(required_keys).unwrap();
    buf.write_u64::<BigEndian>(nonce).unwrap();

    // Compose data to hash
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut creator);
    buf.append(&mut address);
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut keys);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &OpenMultiSig) -> Vec<u8> {
    let mut address = if let Some(ref address) = obj.address {
        address.to_bytes()
    } else {
        panic!("Address field is missing");
    };

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(obj.keys.len());
        
    for k in obj.keys.iter() {
        keys.push(k.to_bytes());
    }

    // Encode keys
    let mut keys: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&keys);

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let currency_hash = &obj.currency_hash.0;
    let mut amount = obj.amount.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let nonce = obj.nonce;
    let required_keys = obj.required_keys;

    buf.write_u8(required_keys).unwrap();
    buf.write_u64::<BigEndian>(nonce).unwrap();

    // Compose data to hash
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut currency_hash.to_vec());
    buf.append(&mut creator);
    buf.append(&mut address);
    buf.append(&mut amount);
    buf.append(&mut fee);
    buf.append(&mut keys);

    buf
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

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;

    quickcheck! {
        fn serialize_deserialize(tx: OpenMultiSig) -> bool {
            tx == OpenMultiSig::from_bytes(&OpenMultiSig::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: OpenMultiSig) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            keys: Vec<NormalAddress>,
            required_keys: u8,
            amount: Balance,
            currency_hash: Hash,
            fee: Balance,
            fee_hash: Hash,
            address: MultiSigAddress,
            nonce: u64
        ) -> bool {
            let id = Identity::new();

            let mut tx = OpenMultiSig {
                creator: NormalAddress::from_pkey(*id.pkey()),
                keys: keys,
                required_keys: required_keys,
                amount: amount,
                currency_hash: currency_hash,
                fee: fee,
                fee_hash: fee_hash,
                nonce: nonce,
                address: Some(address),
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}