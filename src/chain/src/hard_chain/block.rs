/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

use crate::types::*;
use crate::block::Block;
use crate::chain::ChainErr;
use crate::easy_chain::block::EasyBlock;
use crate::hard_chain::state::HardChainState;
use account::NormalAddress;
use bin_tools::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use crypto::Hash;
use crypto::PublicKey;
use lazy_static::*;
use miner::{Proof, PROOF_SIZE};
use std::boxed::Box;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::str::FromStr;
use std::sync::Arc;

lazy_static! {
    /// Atomic reference count to hard chain genesis block
    static ref GENESIS_RC: Arc<HardBlock> = {
        let mut block = HardBlock {
            easy_block_hash: None,
            parent_hash: None,
            proof: Proof::zero(PROOF_SIZE),
            collector_address: NormalAddress::from_pkey(PublicKey([0; 32])),
            height: 0,
            nonce: 0,
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
    easy_block_hash: Option<Hash>,

    /// The height of the block.
    height: u64,

    /// The address that will collect the
    /// rewards earned by the miner.
    collector_address: NormalAddress,

    /// The hash of the parent block.
    parent_hash: Option<Hash>,

    /// The block's proof of work
    proof: Proof,

    /// Proof of work nonce
    nonce: u32,

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
    type ChainState = HardChainState;

    fn genesis() -> Arc<HardBlock> {
        GENESIS_RC.clone()
    }

    fn is_genesis(&self) -> bool {
        self == GENESIS_RC.as_ref()
    }

    fn genesis_state() -> HardChainState {
        HardChainState::genesis()
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
        let fun = |block| {};

        Some(Box::new(fun))
    }

    fn append_condition(
        block: Arc<HardBlock>,
        chain_state: Self::ChainState,
        branch_type: BranchType,
    ) -> Result<Self::ChainState, ChainErr> {
        let easy_block_hash = block.easy_block_hash.unwrap();

        // TODO: Validate difficulty
        // TODO: Validate proof of work

        {
            let easy_chain = &chain_state.easy_chain.chain.read();

            match branch_type {
                // Canonical branch validations
                BranchType::Canonical => {
                    if let Some(easy_block) = chain_state.easy_chain.query(&easy_block_hash) {
                        if easy_block.height() < chain_state.last_easy_height {
                            return Err(ChainErr::BadAppendCondition);
                        }
                        
                        // The referred block must be the canonical tip
                        if easy_block.height() != easy_chain.canonical_tip_height() {
                            return Err(ChainErr::BadAppendCondition);
                        }
                    } else {
                        // Reject blocks that don't have a corresponding 
                        // block in the easy chain.
                        return Err(ChainErr::BadAppendCondition);
                    }
                }

                // Non-canonical branch validations
                BranchType::NonCanonical => {
                    if let Some(easy_block) = chain_state.easy_chain.query(&easy_block_hash) {
                        unimplemented!();
                    } else if let Some(easy_block) = easy_chain.query_orphan(&easy_block_hash) {
                        let orphan_type = easy_chain.orphan_type(&easy_block_hash).unwrap();

                        unimplemented!();
                    } else {
                        // Reject blocks that don't have a corresponding 
                        // block in the easy chain.
                        return Err(ChainErr::BadAppendCondition);
                    }
                }
            }
        }

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
        buf.write_u32::<BigEndian>(self.nonce).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.hash.unwrap().0);
        buf.extend_from_slice(&self.easy_block_hash.as_ref().unwrap().0);
        buf.extend_from_slice(&self.parent_hash.unwrap().0);
        buf.extend_from_slice(&self.collector_address.to_bytes());
        buf.extend_from_slice(&self.proof.to_bytes());
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

        let nonce = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        rdr.set_position(7);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        buf.drain(..15);

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
                _ => return Err("Incorrect address field"),
            }
        } else {
            return Err("Incorrect packet structure 5");
        };

        let proof = if buf.len() > 1 + 8 * PROOF_SIZE {
            let proof: Vec<u8> = buf.drain(..(1 + 8 * PROOF_SIZE)).collect();

            match Proof::from_bytes(&proof) {
                Ok(proof) => proof,
                _ => return Err("Incorrect proof field"),
            }
        } else {
            return Err("Incorrect packet structure 6");
        };

        let address = if buf.len() > address_len as usize {
            let address_vec: Vec<u8> = buf.drain(..address_len as usize).collect();

            match str::from_utf8(&address_vec) {
                Ok(result) => match SocketAddr::from_str(result) {
                    Ok(addr) => addr,
                    Err(_) => return Err("Invalid ip address"),
                },
                Err(_) => return Err("Invalid ip address"),
            }
        } else {
            return Err("Incorrect packet structure 7");
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
            easy_block_hash: Some(easy_block_hash),
            collector_address,
            proof,
            nonce,
            hash: Some(hash),
            parent_hash: Some(parent_hash),
            ip: address,
            height,
        }))
    }
}

impl HardBlock {
    pub const BLOCK_TYPE: u8 = 1;

    pub fn new(
        parent_hash: Option<Hash>,
        collector_address: NormalAddress,
        ip: SocketAddr,
        height: u64,
        nonce: u32,
        easy_block_hash: Hash,
        proof: Proof,
    ) -> HardBlock {
        HardBlock {
            parent_hash,
            easy_block_hash: Some(easy_block_hash),
            collector_address,
            height,
            hash: None,
            ip,
            proof,
            nonce,
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
        let encoded_nonce = encode_be_u32!(self.nonce);
        let addr = format!("{}", self.ip);

        buf.extend_from_slice(&encoded_height);
        buf.extend_from_slice(&encoded_nonce);

        if let Some(parent_hash) = self.parent_hash {
            buf.extend_from_slice(&parent_hash.0);
        }

        if let Some(ref easy_block_hash) = self.easy_block_hash {
            buf.extend_from_slice(&easy_block_hash.0);
        }
        
        buf.extend_from_slice(&self.collector_address.to_bytes());
        buf.extend_from_slice(&self.proof.to_bytes());
        buf.extend_from_slice(addr.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());
        buf
    }
}

use quickcheck::*;

impl Arbitrary for HardBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> HardBlock {
        HardBlock {
            easy_block_hash: Some(Arbitrary::arbitrary(g)),
            height: Arbitrary::arbitrary(g),
            collector_address: Arbitrary::arbitrary(g),
            parent_hash: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            ip: Arbitrary::arbitrary(g),
            proof: Proof::random(PROOF_SIZE),
            nonce: Arbitrary::arbitrary(g),
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;

    quickcheck! {
        fn append_condition_integration() -> bool {
            let (easy_chain, hard_chain, state_chain) = init_test_chains();
            let block_generator = BlockGenerator::new(easy_chain.clone(), hard_chain.clone(), state_chain);

            // Generate 10 sets of 1 valid hard block, 1 invalid hard 
            // block and 3 valid easy blocks and 2 invalid easy blocks
            for _ in 0..10 {
                for _ in 0..3 {
                    easy_chain.append_block(block_generator.next_valid_easy().unwrap()).unwrap();
                }

                // Try to append 2 invalid easy blocks
                assert_eq!(easy_chain.append_block(block_generator.next_invalid_easy().unwrap()), Err(ChainErr::BadAppendCondition));
                assert_eq!(easy_chain.append_block(block_generator.next_invalid_easy().unwrap()), Err(ChainErr::BadAppendCondition));

                easy_chain.append_block(block_generator.next_valid_easy().unwrap()).unwrap();
                assert_eq!(hard_chain.append_block(block_generator.next_invalid_hard().unwrap()), Err(ChainErr::BadAppendCondition));
            }

            {
                let easy_chain = easy_chain.chain.read();
                let hard_chain = hard_chain.chain.read();
            
                assert_eq!(easy_chain.height(), 30);
                assert_eq!(hard_chain.height(), 10);
            }

            true
        }

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
