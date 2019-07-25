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
use crate::chain::ChainErr;
use crate::easy_chain::block::EasyBlock;
use crate::pow_chain_state::PowChainState;
use account::NormalAddress;
use crypto::PublicKey;
use bin_tools::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use crypto::Hash;
use lazy_static::*;
use std::boxed::Box;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;
use std::str;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The size of the hard block proof
pub const HARD_PROOF_SIZE: usize = 42;

lazy_static! {
    /// Atomic reference count to hard chain genesis block
    static ref GENESIS_RC: Arc<HardBlock> = {
        let easy_block_hash = EasyBlock::genesis().block_hash().unwrap();

        let mut block = HardBlock {
            easy_block_hash,
            parent_hash: None,
            collector_address: NormalAddress::from_pkey(PublicKey([0; 32])),
            height: 0,
            hash: None,
            ip: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 44034),
            timestamp: Utc.ymd(2018, 4, 1).and_hms(9, 10, 11), // TODO: Change this accordingly
        };

        block.compute_hash();

        Arc::new(block)
    };
}

#[derive(Clone, Debug)]
/// A block belonging to the `HardChain`.
pub struct HardBlock {
    /// A reference to a block in the `EasyChain`.
    easy_block_hash: Hash,

    /// The height of the block.
    height: u64,

    /// The address that will collect the 
    /// rewards earned by the miner.
    collector_address: NormalAddress,

    /// The hash of the parent block.
    parent_hash: Option<Hash>,

    /// The hash of the block.
    hash: Option<Hash>,

    /// The timestamp of the block.
    timestamp: DateTime<Utc>,

    /// Ip of the miner
    ip: SocketAddr,
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
    type ChainState = PowChainState;

    fn genesis() -> Arc<HardBlock> {
        GENESIS_RC.clone()
    }

    fn is_genesis(&self) -> bool {
        self == GENESIS_RC.as_ref()
    }

    fn genesis_state() -> PowChainState {
        PowChainState::genesis()
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

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn address(&self) -> Option<&SocketAddr> {
        Some(&self.ip)
    }

    fn after_write() -> Option<Box<FnMut(Arc<HardBlock>)>> {
        let fun = |block| {

        };
        
        Some(Box::new(fun))
    }

    fn append_condition(_block: Arc<HardBlock>, chain_state: Self::ChainState) -> Result<Self::ChainState, ChainErr> {
        Ok(chain_state)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let ts = self.timestamp.to_rfc3339();
        let address = format!("{}", self.ip);
        let address = address.as_bytes();
        let address_len = address.len() as u8;
        let timestamp = ts.as_bytes();
        let timestamp_len = timestamp.len() as u8;

        buf.write_u8(Self::BLOCK_TYPE).unwrap();
        buf.write_u8(address_len).unwrap();
        buf.write_u8(timestamp_len).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.hash.unwrap().0.to_vec());
        buf.extend_from_slice(&self.easy_block_hash.0.to_vec());
        buf.extend_from_slice(&self.parent_hash.unwrap().0.to_vec());
        buf.extend_from_slice(&self.collector_address.to_bytes());
        buf.extend_from_slice(address);
        buf.extend_from_slice(&timestamp);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<HardBlock>, &'static str> {
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

        let address_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        rdr.set_position(2);

        let timestamp_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        rdr.set_position(3);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        buf.drain(..11);

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

        let collector_address = if buf.len() > 33 as usize {
            let addr: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&addr) {
                Ok(address) => address,
                _ => return Err("Incorrect address field")
            }
        } else {
            return Err("Incorrect packet structure 5");
        };

        let address = if buf.len() > address_len as usize {
            let address_vec: Vec<u8> = buf.drain(..address_len as usize).collect();

            match str::from_utf8(&address_vec) {
                Ok(result) => match SocketAddr::from_str(result) {
                    Ok(addr) => addr,
                    Err(_) => return Err("Invalid ip address")
                },
                Err(_) => return Err("Invalid ip address")
            }
        } else {
            return Err("Incorrect packet structure 5");
        };

        let timestamp = if buf.len() == timestamp_len as usize {
            match std::str::from_utf8(&buf) {
                Ok(utf8) => match DateTime::<Utc>::from_str(utf8) {
                    Ok(timestamp) => timestamp,
                    Err(_) => return Err("Invalid block timestamp"),
                },
                Err(_) => return Err("Invalid block timestamp"),
            }
        } else {
            return Err("Invalid block timestamp");
        };

        Ok(Arc::new(HardBlock {
            timestamp,
            easy_block_hash,
            collector_address,
            hash: Some(hash),
            parent_hash: Some(parent_hash),
            ip: address,
            height,
        }))
    }
}

impl HardBlock {
    pub const BLOCK_TYPE: u8 = 1;

    pub fn new(parent_hash: Option<Hash>, collector_address: NormalAddress, ip: SocketAddr, height: u64, easy_block_hash: Hash) -> HardBlock {
        HardBlock {
            parent_hash,
            easy_block_hash,
            collector_address,
            height,
            hash: None,
            ip,
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

        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());

        buf
    }
}

use quickcheck::*;

impl Arbitrary for HardBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> HardBlock {
        HardBlock {
            easy_block_hash: Arbitrary::arbitrary(g),
            height: Arbitrary::arbitrary(g),
            collector_address: Arbitrary::arbitrary(g),
            parent_hash: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            ip: Arbitrary::arbitrary(g),
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
