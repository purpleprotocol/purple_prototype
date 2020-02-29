/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

use account::{Address, Balance, NormalAddress};
use bitvec::Bits;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, PublicKey as Pk, SecretKey as Sk, ShortHash, Signature};
use patricia_trie::{Trie, TrieDB, TrieDBMut, TrieMut};
use persistence::{Codec, DbHasher};
use rand::Rng;
use std::io::Cursor;

pub const ASSET_NAME_SIZE: usize = 32;
pub const META_FIELD_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct CreateUnique {
    /// The asset creator's address
    pub(crate) creator: Pk,

    /// The next address of the creator
    pub(crate) next_address: NormalAddress,

    /// The receiver of the asset
    pub(crate) receiver: Address,

    /// The global identifier of the asset
    pub(crate) asset_hash: ShortHash,

    /// The id of the currency that the transaction is paid in
    pub(crate) fee_hash: ShortHash,

    /// The name of the asset
    pub(crate) name: [u8; ASSET_NAME_SIZE],

    // 5 optional fields of 32 bytes for metadata. 160 bytes in total.
    pub(crate) meta1: Option<[u8; META_FIELD_SIZE]>,
    pub(crate) meta2: Option<[u8; META_FIELD_SIZE]>,
    pub(crate) meta3: Option<[u8; META_FIELD_SIZE]>,
    pub(crate) meta4: Option<[u8; META_FIELD_SIZE]>,
    pub(crate) meta5: Option<[u8; META_FIELD_SIZE]>,

    /// The fee of the transaction
    pub(crate) fee: Balance,

    // Nonce
    pub(crate) nonce: u64,

    pub(crate) hash: Option<Hash>,

    pub(crate) signature: Option<Signature>,
}

impl CreateUnique {
    pub const TX_TYPE: u8 = 9;

    /// Validates the transaction against the provided state.
    pub fn validate(&self, trie: &TrieDB<DbHasher, Codec>) -> bool {
        unimplemented!();
    }

    /// Applies the burn transaction to the provided database.
    pub fn apply(&self, trie: &mut TrieDBMut<DbHasher, Codec>) {
        unimplemented!();
    }

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
            Some(ref sig) => crypto::verify(&message, sig, &self.creator),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(9)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Meta Exist BitMask   - 8bits
    /// 4) Nonce                - 64bits
    /// 5) Currency flag        - 1byte (Value is 1 if currency and fee hashes are identical. Otherwise is 0)
    /// 6) Asset hash           - 8byte binary
    /// 7) Fee hash             - 8byte binary (Non-existent if currency flag is true)
    /// 8) Creator              - 33byte binary
    /// 9) Receiver             - 33byte binary
    /// 10) Next address        - 33byte binary
    /// 11) Name                - 32byte binary
    /// 12) Signature           - 64byte binary
    /// 13) Fee                 - Binary of fee length
    /// 14) Meta1 (Optional)    - 32byte binary
    /// 15) Meta2 (Optional)    - 32byte binary
    /// 16) Meta3 (Optional)    - 32byte binary
    /// 17) Meta4 (Optional)    - 32byte binary
    /// 18) Meta5 (Optional)    - 32byte binary
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();
        let mut bitmask: u8 = 0;

        let mut signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        if let Some(_meta1) = &self.meta1 {
            bitmask.set(0, true);
        };
        if let Some(_meta2) = &self.meta2 {
            bitmask.set(1, true);
        };
        if let Some(_meta3) = &self.meta3 {
            bitmask.set(2, true);
        };
        if let Some(_meta4) = &self.meta4 {
            bitmask.set(3, true);
        };
        if let Some(_meta5) = &self.meta5 {
            bitmask.set(4, true);
        };

        let tx_type: u8 = Self::TX_TYPE;
        let receiver = self.receiver.to_bytes();
        let next_address = self.next_address.to_bytes();
        let asset_hash = &self.asset_hash.0;
        let fee_hash = &self.fee_hash.0;
        let name = &self.name;
        let fee = self.fee.to_bytes();
        let fee_len = fee.len();
        let nonce = &self.nonce;
        let currency_flag = if asset_hash == fee_hash { 1 } else { 0 };

        // Write to buffer
        buf.write_u8(tx_type).unwrap();
        buf.write_u8(fee_len as u8).unwrap();
        buf.write_u8(bitmask).unwrap();
        buf.write_u64::<BigEndian>(*nonce).unwrap();
        buf.write_u8(currency_flag).unwrap();
        buf.extend_from_slice(asset_hash);

        if currency_flag == 0 {
            buf.extend_from_slice(fee_hash);
        }

        buf.extend_from_slice(&self.creator.0);
        buf.extend_from_slice(&receiver);
        buf.extend_from_slice(&next_address);
        buf.extend_from_slice(name);
        buf.extend_from_slice(&signature);
        buf.extend_from_slice(&fee);

        if bitmask.get(0) {
            let meta1 = &self.meta1.unwrap();
            buf.extend_from_slice(&meta1[..]);
        };
        if bitmask.get(1) {
            let meta2 = &self.meta2.unwrap();
            buf.extend_from_slice(&meta2[..]);
        };
        if bitmask.get(2) {
            let meta3 = &self.meta3.unwrap();
            buf.extend_from_slice(&meta3[..]);
        };
        if bitmask.get(3) {
            let meta4 = &self.meta4.unwrap();
            buf.extend_from_slice(&meta4[..]);
        };
        if bitmask.get(4) {
            let meta5 = &self.meta5.unwrap();
            buf.extend_from_slice(&meta5[..]);
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

        rdr.set_position(2);

        let bitmask = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad bitmask");
        };

        rdr.set_position(3);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        rdr.set_position(11);

        let currency_flag = if let Ok(result) = rdr.read_u8() {
            if result == 0 || result == 1 {
                result
            } else {
                return Err("Bad currency flag value");
            }
        } else {
            return Err("Bad currency flag");
        };

        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..12).collect();

        let asset_hash = if buf.len() > 8 as usize {
            let mut hash = [0; 8];
            let hash_vec: Vec<u8> = buf.drain(..8).collect();

            hash.copy_from_slice(&hash_vec);

            ShortHash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let fee_hash = if currency_flag == 1 {
            asset_hash
        } else {
            if buf.len() > 8 as usize {
                let mut hash = [0; 8];
                let hash_vec: Vec<u8> = buf.drain(..8).collect();

                hash.copy_from_slice(&hash_vec);

                ShortHash(hash)
            } else {
                return Err("Incorrect packet structure");
            }
        };

        let creator = if buf.len() > 32 as usize {
            let creator_vec: Vec<u8> = buf.drain(..32).collect();
            let mut creator_bytes = [0; 32];

            creator_bytes.copy_from_slice(&creator_vec);
            Pk(creator_bytes)
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

        let next_address = if buf.len() > 33 as usize {
            let next_address_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&next_address_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
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

        if bitmask.get(0) {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta1 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if bitmask.get(1) {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta2 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if bitmask.get(2) {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta3 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if bitmask.get(3) {
            if buf.len() >= META_FIELD_SIZE as usize {
                let mut meta_vec = [0; META_FIELD_SIZE];
                let meta_from_buf: Vec<u8> = buf.drain(..32).collect();

                meta_vec.copy_from_slice(&meta_from_buf);
                meta4 = Some(meta_vec);
            } else {
                return Err("Incorrect packet structure");
            }
        }

        if bitmask.get(4) {
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
            return Err("Incorrect packet structure. Buffer still has data after all fields were deserialized");
        };

        let mut create_unique = CreateUnique {
            creator,
            receiver,
            next_address,
            asset_hash,
            fee_hash,
            name,
            meta1,
            meta2,
            meta3,
            meta4,
            meta5,
            fee,
            nonce,
            hash: None,
            signature: Some(signature),
        };

        create_unique.compute_hash();
        Ok(create_unique)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<DbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &CreateUnique) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let next_address = obj.next_address.to_bytes();
    let receiver = obj.receiver.to_bytes();
    let name = obj.name;
    let fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to hash
    buf.write_u64::<BigEndian>(obj.nonce).unwrap();
    buf.extend_from_slice(&obj.creator.0);
    buf.extend_from_slice(&receiver);
    buf.extend_from_slice(&next_address);
    buf.extend_from_slice(&name);

    // Write meta if present
    if let Some(meta) = obj.meta1 {
        buf.extend_from_slice(&meta);
    }

    if let Some(meta) = obj.meta2 {
        buf.extend_from_slice(&meta);
    }

    if let Some(meta) = obj.meta3 {
        buf.extend_from_slice(&meta);
    }

    if let Some(meta) = obj.meta4 {
        buf.extend_from_slice(&meta);
    }

    if let Some(meta) = obj.meta5 {
        buf.extend_from_slice(&meta);
    }

    buf.extend_from_slice(&asset_hash);
    buf.extend_from_slice(&fee_hash);
    buf.extend_from_slice(&fee);

    buf
}

use quickcheck::Arbitrary;

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

        let (pk, _) = crypto::gen_keypair();
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);

        let asset_hash = Arbitrary::arbitrary(g);
        let fee_hash = if random == 1 {
            asset_hash
        } else {
            Arbitrary::arbitrary(g)
        };

        let mut tx = CreateUnique {
            creator: pk,
            next_address: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            asset_hash,
            name: name.0,
            meta1,
            meta2,
            meta3,
            meta4,
            meta5,
            fee_hash,
            fee: Arbitrary::arbitrary(g),
            nonce: Arbitrary::arbitrary(g),
            hash: None,
            signature: Some(Arbitrary::arbitrary(g)),
        };

        tx.compute_hash();
        tx
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
                tx.compute_hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            receiver: Address,
            fee: Balance,
            name: Array32,
            meta: (Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>),
            asset_hash: ShortHash,
            fee_hash: ShortHash
        ) -> bool {
            let id = Identity::new();
            let id2 = Identity::new();
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
                creator: id.pkey().clone(),
                next_address: NormalAddress::from_pkey(id2.pkey()),
                receiver: receiver,
                name: name.0,
                meta1,
                meta2,
                meta3,
                meta4,
                meta5,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                nonce: 1,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
