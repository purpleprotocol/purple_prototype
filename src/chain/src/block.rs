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

use crate::{EasyBlock, HardBlock};
use chrono::prelude::*;
use crypto::Hash;
use std::boxed::Box;
use std::sync::Arc;
use std::net::SocketAddr;

/// Generic block interface
pub trait Block {
    /// Returns the genesis block.
    fn genesis() -> Arc<Self>;

    /// Returns the hash of the block.
    fn block_hash(&self) -> Option<Hash>;

    /// Returns the merkle root hash of the block.
    fn merkle_root(&self) -> Option<Hash>;

    /// Returns the parent hash of the block.
    fn parent_hash(&self) -> Option<Hash>;

    /// Returns the timestamp of the block.
    fn timestamp(&self) -> DateTime<Utc>;

    /// Returns the height of the block.
    fn height(&self) -> u64;

    /// Returns the ip of the block's miner
    fn address(&self) -> Option<&SocketAddr>;

    /// Callback that executes after a block is written to a chain.
    fn after_write() -> Option<Box<FnMut(Arc<Self>)>>;

    /// Serializes the block.
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserializes the block
    fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>, &'static str>;
}

/// Wrapper enum used **only** for serialization/deserialization
#[derive(Clone, Debug, PartialEq)]
pub enum BlockWrapper {
    EasyBlock(Arc<EasyBlock>),
    HardBlock(Arc<HardBlock>)
}

impl BlockWrapper {
    pub fn from_bytes(bytes: &[u8]) -> Result<Arc<BlockWrapper>, &'static str> {
        let first_byte = bytes[0];

        match first_byte {
            EasyBlock::BLOCK_TYPE => Ok(Arc::new(BlockWrapper::EasyBlock(EasyBlock::from_bytes(bytes)?))),
            HardBlock::BLOCK_TYPE => Ok(Arc::new(BlockWrapper::HardBlock(HardBlock::from_bytes(bytes)?))),
            _ => return Err("Invalid block type")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            BlockWrapper::EasyBlock(block) => block.to_bytes(),
            BlockWrapper::HardBlock(block) => block.to_bytes(),
        }
    }

    pub fn block_hash(&self) -> Option<Hash> {
        match self {
            BlockWrapper::EasyBlock(block) => block.block_hash(),
            BlockWrapper::HardBlock(block) => block.block_hash(),
        }
    }
}

impl quickcheck::Arbitrary for BlockWrapper {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> BlockWrapper {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);

        match random {
            0 => BlockWrapper::EasyBlock(quickcheck::Arbitrary::arbitrary(g)),
            1 => BlockWrapper::HardBlock(quickcheck::Arbitrary::arbitrary(g)),
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    quickcheck! {
        fn wrapper_serialize_deserialize(block: BlockWrapper) -> bool {
            BlockWrapper::from_bytes(&BlockWrapper::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap();

            true
        }
    }
}