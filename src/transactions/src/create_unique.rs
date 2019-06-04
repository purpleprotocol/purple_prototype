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

use account::{NormalAddress, Address, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, Signature, PublicKey as Pk, SecretKey as Sk};

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
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, &skey);

        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.creator.pkey()),
            None => false,
        }
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &CreateUnique) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

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
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &CreateUnique) -> Vec<u8> {
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
        // fn serialize_deserialize(tx: CreateUnique) -> bool {
        //     tx == CreateUnique::from_bytes(&CreateUnique::to_bytes(&tx).unwrap()).unwrap()
        // }

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
