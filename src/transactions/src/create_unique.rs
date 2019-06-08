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

use account::{Address, Balance, NormalAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;

pub const ASSET_NAME_SIZE: usize = 32;
pub const META_FIELD_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateUnique {
    /// The asset creator's address
    pub creator: NormalAddress,

    /// The receiver of the asset
    pub receiver: Address,

    /// The global identifier of the asset
    pub asset_hash: Hash,

    /// The id of the currency that the transaction is paid in
    pub fee_hash: Hash,

    /// The name of the asset
    pub name: [u8; ASSET_NAME_SIZE],

    // 5 optional fields of 32 bytes for metadata. 160 bytes in total.
    pub meta1: Option<[u8; META_FIELD_SIZE]>,
    pub meta2: Option<[u8; META_FIELD_SIZE]>,
    pub meta3: Option<[u8; META_FIELD_SIZE]>,
    pub meta4: Option<[u8; META_FIELD_SIZE]>,
    pub meta5: Option<[u8; META_FIELD_SIZE]>,

    /// The fee of the transaction
    pub fee: Balance,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl CreateUnique {
    pub const TX_TYPE: u8 = 9;

    /// Signs the transaction with the given secret key.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign(&message, &skey);

        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.creator.pkey()),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(9)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Meta Existence Map   - 5byte binary
    /// 4) Creator              - 33byte binary
    /// 5) Receiver             - 33byte binary
    /// 6) Asset hash           - 32byte binary
    /// 7) Fee hash             - 32byte binary
    /// 8) Name                 - 32byte binary
    /// 9) Hash                 - 32byte binary
    /// 10) Signature           - 64byte binary
    /// 11) Fee                 - Binary of fee length
    /// 12) Meta1 (Optional)    - 32byte binary
    /// 13) Meta2 (Optional)    - 32byte binary
    /// 14) Meta3 (Optional)    - 32byte binary
    /// 15) Meta4 (Optional)    - 32byte binary
    /// 16) Meta5 (Optional)    - 32byte binary
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();
        let mut meta_exist: Vec<u8> = vec![0, 0, 0, 0, 0];

        // Prepare the fields
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

        if let Some(_meta1) = &self.meta1 {
            meta_exist[0] = 1;
        };
        if let Some(_meta2) = &self.meta2 {
            meta_exist[1] = 1;
        };
        if let Some(_meta3) = &self.meta3 {
            meta_exist[2] = 1;
        };
        if let Some(_meta4) = &self.meta4 {
            meta_exist[3] = 1;
        };
        if let Some(_meta5) = &self.meta5 {
            meta_exist[4] = 1;
        };

        let tx_type: u8 = Self::TX_TYPE;
        let creator = &self.creator.to_bytes();
        let receiver = &self.receiver.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let name = &self.name;
        let fee = &self.fee.to_bytes();
        let fee_len = fee.len();

        // Write to buffer
        buf.write_u8(tx_type).unwrap();
        buf.write_u8(fee_len as u8).unwrap();
        buf.extend_from_slice(&mut meta_exist);
        buf.append(&mut creator.to_vec());
        buf.append(&mut receiver.to_vec());

        buf.append(&mut asset_hash.to_vec());
        buf.append(&mut fee_hash.to_vec());
        buf.append(&mut name.to_vec());
        buf.append(&mut hash.to_vec());
        buf.append(&mut signature);
        buf.append(&mut fee.to_vec());

        if meta_exist[0] == 1 {
            let meta1 = &self.meta1.unwrap();
            buf.append(&mut meta1.to_vec());
        };
        if meta_exist[1] == 1 {
            let meta2 = &self.meta2.unwrap();
            buf.append(&mut meta2.to_vec());
        };
        if meta_exist[2] == 1 {
            let meta3 = &self.meta3.unwrap();
            buf.append(&mut meta3.to_vec());
        };
        if meta_exist[3] == 1 {
            let meta4 = &self.meta4.unwrap();
            buf.append(&mut meta4.to_vec());
        };
        if meta_exist[4] == 1 {
            let meta5 = &self.meta5.unwrap();
            buf.append(&mut meta5.to_vec());
        };

        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<CreateUnique, &'static str> {
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

        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..2).collect();

        let meta_exist = if buf.len() > 5 as usize {
            let mut meta_existence = [0; 5];
            let meta_exist_vec: Vec<u8> = buf.drain(..5).collect();

            meta_existence.copy_from_slice(&meta_exist_vec);
            meta_existence
        } else {
            return Err("Bad meta existence information");
        };

        let creator = if buf.len() > 33 as usize {
            let creator_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&creator_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 33 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..33).collect();

            match Address::from_bytes(&receiver_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let asset_hash = if buf.len() > 32 as usize {
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

        let name = if buf.len() > 32 as usize {
            let mut name_vec = [0; ASSET_NAME_SIZE];
            let name_vec_from_buf: Vec<u8> = buf.drain(..32).collect();

            name_vec.copy_from_slice(&name_vec_from_buf);
            name_vec
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

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_) => return Err("Bad signature"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let fee = if buf.len() >= fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad gas price"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        // From this point, data can be missing (None values are not serialized)
        let mut meta1: Option<[u8; META_FIELD_SIZE]> = None;
        let mut meta2: Option<[u8; META_FIELD_SIZE]> = None;
        let mut meta3: Option<[u8; META_FIELD_SIZE]> = None;
        let mut meta4: Option<[u8; META_FIELD_SIZE]> = None;
        let mut meta5: Option<[u8; META_FIELD_SIZE]> = None;

        if meta_exist[0] == 1 {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta1 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if meta_exist[1] == 1 {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta2 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if meta_exist[2] == 1 {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta3 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if meta_exist[3] == 1 {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta4 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if meta_exist[4] == 1 {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta5 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        // Make sure no data remained
        if buf.len() > 0 {
            return Err("Buffer still has data after all fields were deserialized");
        };

        let create_unique = CreateUnique {
            creator: creator,
            receiver: receiver,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            name: name,
            meta1: meta1,
            meta2: meta2,
            meta3: meta3,
            meta4: meta4,
            meta5: meta5,
            fee: fee,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(create_unique)
    }

    impl_hash!();
}

fn assemble_message(obj: &CreateUnique) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let mut name = obj.name;
    let mut fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to hash
    buf.append(&mut creator);
    buf.append(&mut receiver);
    buf.append(&mut name.to_vec());

    // Write meta if present
    if let Some(meta) = obj.meta1 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta2 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta3 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta4 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta5 {
        buf.append(&mut meta.to_vec());
    }

    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;
use rand::Rng;

#[derive(Clone, Debug)]
struct Array32(pub [u8; 32]);

impl Arbitrary for Array32 {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Array32 {
        Array32(rand::thread_rng().gen::<[u8; 32]>())
    }
}

impl Arbitrary for CreateUnique {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> CreateUnique {
        let name: Array32 = Arbitrary::arbitrary(g);
        let meta1: Option<Array32> = Arbitrary::arbitrary(g);
        let meta2: Option<Array32> = Arbitrary::arbitrary(g);
        let meta3: Option<Array32> = Arbitrary::arbitrary(g);
        let meta4: Option<Array32> = Arbitrary::arbitrary(g);
        let meta5: Option<Array32> = Arbitrary::arbitrary(g);

        let meta1 = if let Some(Array32(result)) = meta1 {
            Some(result)
        } else {
            None
        };

        let meta2 = if let Some(Array32(result)) = meta2 {
            Some(result)
        } else {
            None
        };

        let meta3 = if let Some(Array32(result)) = meta3 {
            Some(result)
        } else {
            None
        };

        let meta4 = if let Some(Array32(result)) = meta4 {
            Some(result)
        } else {
            None
        };

        let meta5 = if let Some(Array32(result)) = meta5 {
            Some(result)
        } else {
            None
        };

        CreateUnique {
            creator: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            name: name.0,
            meta1: meta1,
            meta2: meta2,
            meta3: meta3,
            meta4: meta4,
            meta5: meta5,
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
    use account::NormalAddress;
    use crypto::Identity;

    quickcheck! {
        fn serialize_deserialize(tx: CreateUnique) -> bool {
            tx == CreateUnique::from_bytes(&CreateUnique::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: CreateUnique) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            receiver: Address,
            fee: Balance,
            name: Array32,
            meta: (Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>),
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();
            let (
                meta1,
                meta2,
                meta3,
                meta4,
                meta5
            ) = meta;

            let meta1 = if let Some(Array32(result)) = meta1 {
                Some(result)
            } else {
                None
            };

            let meta2 = if let Some(Array32(result)) = meta2 {
                Some(result)
            } else {
                None
            };

            let meta3 = if let Some(Array32(result)) = meta3 {
                Some(result)
            } else {
                None
            };

            let meta4 = if let Some(Array32(result)) = meta4 {
                Some(result)
            } else {
                None
            };

            let meta5 = if let Some(Array32(result)) = meta5 {
                Some(result)
            } else {
                None
            };

            let mut tx = CreateUnique {
                creator: NormalAddress::from_pkey(*id.pkey()),
                receiver: receiver,
                name: name.0,
                meta1: meta1,
                meta2: meta2,
                meta3: meta3,
                meta4: meta4,
                meta5: meta5,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
