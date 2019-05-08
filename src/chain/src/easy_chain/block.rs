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
use chrono::prelude::*;
use crypto::Hash;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::sync::Arc;
use std::boxed::Box;
use bin_tools::*;
use lazy_static::*;

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

#[derive(Debug)]
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
        unimplemented!();
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<EasyBlock>, &'static str> {
        unimplemented!();
    }
}

impl EasyBlock {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_verifies_hashes() {
        let block = EasyBlock::genesis();
        assert!(block.verify_hash());
    }
}