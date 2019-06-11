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
use bin_tools::*;
use chrono::prelude::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::Hash;
use lazy_static::*;
use std::io::Cursor;
use std::boxed::Box;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::sync::Arc;
use std::str::FromStr;

lazy_static! {
    /// Atomic reference count to hard chain genesis block
    static ref GENESIS_RC: Arc<EasyBlock> = {
        let hash = Hash::random();
        let mut block = EasyBlock {
            parent_hash: None,
            merkle_root: Some(Hash::NULL),
            height: 0,
            hash: Some(hash),
            timestamp: Utc.ymd(2018, 4, 1).and_hms(9, 10, 11), // TODO: Change this accordingly
        };

        block.compute_hash();
        Arc::new(block)
    };
}

#[derive(Debug, Clone)]
/// A block belonging to the `EasyChain`.
pub struct EasyBlock {
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

impl PartialEq for EasyBlock {
    fn eq(&self, other: &EasyBlock) -> bool {
        // This only makes sense when the block is received
        // when the node is a server i.e. when the block is
        // guaranteed to have a hash because it already passed
        // the parsing stage.
        self.block_hash().unwrap() == other.block_hash().unwrap()
    }
}

impl Eq for EasyBlock {}

impl HashTrait for EasyBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_hash().unwrap().hash(state);
    }
}

impl Block for EasyBlock {
    fn genesis() -> Arc<EasyBlock> {
        GENESIS_RC.clone()
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

    fn after_write() -> Option<Box<FnMut(Arc<EasyBlock>)>> {
        None
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let ts = self.timestamp.to_rfc3339();
        let timestamp = ts.as_bytes();
        let timestamp_len = timestamp.len() as u8;

        buf.write_u8(Self::BLOCK_TYPE).unwrap();
        buf.write_u8(timestamp_len).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.hash.unwrap().0.to_vec());
        buf.extend_from_slice(&self.parent_hash.unwrap().0.to_vec());
        buf.extend_from_slice(&self.merkle_root.unwrap().0.to_vec());
        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<EasyBlock>, &'static str> {
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

        let timestamp_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        rdr.set_position(2);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        buf.drain(..10);

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 1");
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

        let timestamp = if buf.len() == timestamp_len as usize {
            match std::str::from_utf8(&buf) {
                Ok(utf8) => match DateTime::<Utc>::from_str(utf8) {
                    Ok(timestamp) => timestamp,
                    Err(_) => return Err("Invalid block timestamp 1"),
                },
                Err(_) => return Err("Invalid block timestamp 2"),
            }
        } else {
            return Err("Invalid block timestamp 3");
        };

        Ok(Arc::new(EasyBlock {
            merkle_root: Some(merkle_root),
            timestamp,
            hash: Some(hash),
            parent_hash: Some(parent_hash),
            height,
        }))
    }
}

impl EasyBlock {
    pub const BLOCK_TYPE: u8 = 2;

    pub fn new(parent_hash: Option<Hash>, height: u64) -> EasyBlock {
        EasyBlock {
            parent_hash,
            height,
            merkle_root: None,
            hash: None,
            timestamp: Utc::now(),
        }
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
}

impl quickcheck::Arbitrary for EasyBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> EasyBlock {
        let timestamp = Utc::now();

        EasyBlock {
            height: quickcheck::Arbitrary::arbitrary(g),
            parent_hash: Some(quickcheck::Arbitrary::arbitrary(g)),
            hash: Some(quickcheck::Arbitrary::arbitrary(g)),
            merkle_root: Some(quickcheck::Arbitrary::arbitrary(g)),
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    #[test]
    fn it_verifies_hashes() {
        let block = EasyBlock::genesis();
        assert!(block.verify_hash());
    }

    quickcheck! {
        fn serialize_deserialize(block: EasyBlock) -> bool {
            EasyBlock::from_bytes(&EasyBlock::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap();

            true
        }
    }
}
