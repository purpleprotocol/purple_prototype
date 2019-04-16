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

use crate::block::Block;
use crate::easy_chain::block::EasyBlock;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use crypto::Hash;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::io::Cursor;
use std::str::FromStr;
use bin_tools::*;

/// The size of the hard block proof
pub const HARD_PROOF_SIZE: usize = 42;

#[derive(Clone, Debug)]
/// A block belonging to the `HardChain`.
pub struct HardBlock {
    /// A reference to a block in the `EasyChain`.
    easy_block_hash: Hash,

    /// The height of the block.
    height: u64,

    /// The hash of the parent block.
    parent_hash: Option<Hash>,

    /// The merkle root hash of the block.
    merkle_root: Option<Hash>,

    /// The hash of the block.
    hash: Option<Hash>,

    /// The timestamp of the block.
    timestamp: DateTime<Utc>,
}

impl PartialEq for HardBlock {
    fn eq(&self, other: &HardBlock) -> bool {
        // This only makes sense when the block is received
        // when the node is a server i.e. when the block is
        // guaranteed to have a hash because it already passed
        // the parsing stage.
        self.block_hash().unwrap() == other.block_hash().unwrap()
    }
}

impl Eq for HardBlock {}

impl HashTrait for HardBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_hash().unwrap().hash(state);
    }
}

impl Block for HardBlock {
    fn genesis() -> HardBlock {
        let easy_block_hash = EasyBlock::genesis().block_hash().unwrap();

        HardBlock {
            easy_block_hash,
            parent_hash: None,
            merkle_root: Some(Hash::NULL),
            height: 0,
            hash: None,
            timestamp: Utc.ymd(2018, 4, 1).and_hms(9, 10, 11), // TODO: Change this accordingly
        }
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn block_hash(&self) -> Option<Hash> {
        self.hash.clone()
    }

    fn parent_hash(&self) -> Option<Hash> {
        self.parent_hash.clone()
    }
    
    fn merkle_root(&self) -> Option<Hash> {
        self.merkle_root.clone()
    }
    
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }
}

impl HardBlock {
    pub const BLOCK_TYPE: u8 = 0;

    pub fn new(parent_hash: Option<Hash>, height: u64, easy_block_hash: Hash) -> HardBlock {
        HardBlock {
            parent_hash,
            easy_block_hash,
            merkle_root: None,
            height,
            hash: None,
            timestamp: Utc::now(),
        }
    }

    pub fn calculate_merkle_root(&mut self) {
        // TODO: Replace this
        self.merkle_root = Some(Hash::NULL);
    }  

    pub fn compute_hash(&mut self) {
        let message = self.compute_hash_message();
        let hash = crypto::hash_slice(&message);

        self.hash = Some(hash);
    }

    pub fn verify_hash(&self) -> bool {
        let message = self.compute_hash_message();
        let oracle = crypto::hash_slice(&message);
    
        self.hash.unwrap() == oracle
    }

    fn compute_hash_message(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let encoded_height = encode_be_u64!(self.height);

        buf.extend_from_slice(&encoded_height);

        if let Some(parent_hash) = self.parent_hash {
            buf.extend_from_slice(&parent_hash.0.to_vec());
        }

        buf.extend_from_slice(&self.merkle_root.unwrap().0.to_vec());
        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());

        buf
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        buf.write_u8(Self::BLOCK_TYPE).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.hash.unwrap().0.to_vec());
        buf.extend_from_slice(&self.easy_block_hash.0.to_vec());
        buf.extend_from_slice(&self.parent_hash.unwrap().0.to_vec());
        buf.extend_from_slice(&self.merkle_root.unwrap().0.to_vec());
        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<HardBlock, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let block_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        if block_type != Self::BLOCK_TYPE {
            return Err("Bad block type");
        }

        rdr.set_position(1);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        buf.drain(..9);
    
        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 1");
        };

        let easy_block_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 2");
        };

        let parent_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 3");
        };

        let merkle_root = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 4");
        };

        let timestamp = match std::str::from_utf8(&buf) {
            Ok(utf8) => match DateTime::<Utc>::from_str(utf8) {
                Ok(timestamp) => timestamp,
                Err(_)        => return Err("Invalid block timestamp")
            }, 
            Err(_) => return Err("Invalid block timestamp")
        };

        Ok(HardBlock {
            merkle_root: Some(merkle_root),
            timestamp,
            easy_block_hash,
            hash: Some(hash),
            parent_hash: Some(parent_hash),
            height,
        })
    }
}

#[cfg(test)]
use quickcheck::*;

#[cfg(test)]
impl Arbitrary for HardBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> HardBlock {
        HardBlock {
            easy_block_hash: Arbitrary::arbitrary(g),
            height: Arbitrary::arbitrary(g),
            parent_hash: Some(Arbitrary::arbitrary(g)),
            merkle_root: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn it_verifies_hashes(block: HardBlock) -> bool {
            let mut block = block.clone();

            assert!(!block.verify_hash());

            block.compute_hash();
            block.verify_hash()
        }

        fn serialize_deserialize(block: HardBlock) -> bool {
            HardBlock::from_bytes(&HardBlock::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap();

            true
        }
    }
}