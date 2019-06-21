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
use crate::hard_chain::block::HardBlock;
use events::Event;
use account::NormalAddress;
use crypto::PublicKey;
use bin_tools::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use crypto::Hash;
use persistence::PersistentDb;
use lazy_static::*;
use std::boxed::Box;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;
use std::net::SocketAddr;
use std::str;
use rlp::{Rlp, RlpStream};

lazy_static! {
    /// Atomic reference count to state chain genesis block
    static ref GENESIS_RC: Arc<StateBlock> = {
        let hard_block_hash = HardBlock::genesis().block_hash().unwrap();

        let mut block = StateBlock {
            hard_block_hash,
            parent_hash: None,
            height: 0,
            epoch: 0,
            hash: None,
            events_root: Some(Hash::NULL),
            // TODO: Replace with genesis state root
            state_root: Hash::NULL,
            events: vec![]
        };

        block.compute_hash();

        Arc::new(block)
    };
}

#[derive(Clone, Debug)]
/// A block belonging to the `StateChain`.
pub struct StateBlock {
    /// A reference to a block in the `HardChain`.
    hard_block_hash: Hash,

    /// The height of the block.
    height: u64,

    /// The corresponding epoch in the validator pool
    epoch: u64,

    /// The hash of the parent block.
    parent_hash: Option<Hash>,

    /// Merkle root hash of all event hashes
    events_root: Option<Hash>,

    /// Root hash of the trie state
    state_root: Hash,

    /// The hash of the block.
    hash: Option<Hash>,

    /// Events stored in the block
    events: Vec<Arc<Event>>,
}

impl PartialEq for StateBlock {
    fn eq(&self, other: &StateBlock) -> bool {
        // This only makes sense when the block is received
        // when the node is a server i.e. when the block is
        // guaranteed to have a hash because it already passed
        // the parsing stage.
        self.block_hash().unwrap() == other.block_hash().unwrap()
    }
}

impl Eq for StateBlock {}

impl HashTrait for StateBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_hash().unwrap().hash(state);
    }
}

impl Block for StateBlock {
    type TipState = PersistentDb;

    fn genesis() -> Arc<StateBlock> {
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

    fn timestamp(&self) -> DateTime<Utc> {
        unimplemented!();
    }

    fn address(&self) -> Option<&SocketAddr> {
        unimplemented!();
    }

    fn after_write() -> Option<Box<FnMut(Arc<StateBlock>)>> {
        let fun = |block| {

        };
        
        Some(Box::new(fun))
    }

    fn append_condition() -> Option<Box<(Fn(Arc<StateBlock>, Self::TipState) -> Result<Self::TipState, ()>)>> {
        None
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let mut rlp = RlpStream::new_list(self.events.len());

        // Encode events
        for e in self.events.iter() {
            rlp.append(&e.to_bytes());
        }

        let events = rlp.out();
        let events_len = events.len();            

        buf.write_u8(Self::BLOCK_TYPE).unwrap();
        buf.write_u32::<BigEndian>(events_len as u32).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.write_u64::<BigEndian>(self.epoch).unwrap();
        buf.extend_from_slice(&self.hash.unwrap().0);
        buf.extend_from_slice(&self.hard_block_hash.0);
        buf.extend_from_slice(&self.parent_hash.unwrap().0);
        buf.extend_from_slice(&self.events_root.unwrap().0);
        buf.extend_from_slice(&self.state_root.0);
        buf.extend_from_slice(&events);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<StateBlock>, &'static str> {
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

        let events_len = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err("Bad events len");
        };

        rdr.set_position(5);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        rdr.set_position(13);

        let epoch = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad epoch");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        buf.drain(..21);

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 1");
        };

        let hard_block_hash = if buf.len() > 32 as usize {
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

        let events_root = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 4");
        };

        let state_root = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 5");
        };

        let events = if buf.len() == events_len as usize {
            let rlp = Rlp::new(&buf);

            if rlp.is_list() {
                let events: Result<Vec<Arc<Event>>, _> = rlp
                    .iter()
                    .map(|data| {
                        if data.is_data() {
                            match data.data() {
                                Ok(data) => Event::from_bytes(&data).map(|e| Arc::new(e)),
                                Err(_) => Err("Invalid event")
                            }
                        } else {
                            return Err("Non data object")
                        }
                    })
                    .collect();
                
                if let Ok(events) = events {
                    events
                } else {
                    return Err("Invalid events");
                }
            } else {
                return Err("Invalid events");
            }
        } else {
            return Err("Incorrect packet structure 6");
        };

        Ok(Arc::new(StateBlock {
            events,
            events_root: Some(events_root),
            state_root,
            hard_block_hash,
            hash: Some(hash),
            parent_hash: Some(parent_hash),
            height,
            epoch,
        }))
    }
}

impl StateBlock {
    pub const BLOCK_TYPE: u8 = 3;

    pub fn new(
        parent_hash: Option<Hash>, 
        state_root: Hash, 
        height: u64, 
        epoch: u64, 
        hard_block_hash: Hash, 
        events: Vec<Arc<Event>>
    ) -> StateBlock {
        StateBlock {
            parent_hash,
            hard_block_hash,
            height,
            epoch,
            state_root,
            events_root: None,
            hash: None,
            events
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
        buf.write_u8(Self::BLOCK_TYPE).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.write_u64::<BigEndian>(self.epoch).unwrap();
        buf.extend_from_slice(&self.hard_block_hash.0);
        
        if let Some(ref parent_hash) = self.parent_hash {
            buf.extend_from_slice(&parent_hash.0);
        }
        
        buf.extend_from_slice(&self.events_root.unwrap().0);
        buf.extend_from_slice(&self.state_root.0);
        buf
    }
}

use quickcheck::*;

impl Arbitrary for StateBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> StateBlock {
        let mut events: Vec<Arc<Event>> = Vec::with_capacity(8);

        for _ in 0..8 {
            events.push(Arbitrary::arbitrary(g));
        }

        StateBlock {
            hard_block_hash: Arbitrary::arbitrary(g),
            height: Arbitrary::arbitrary(g),
            epoch: Arbitrary::arbitrary(g),
            parent_hash: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            events_root: Some(Arbitrary::arbitrary(g)),
            state_root: Arbitrary::arbitrary(g),
            events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn it_verifies_hashes(block: StateBlock) -> bool {
            let mut block = block.clone();

            assert!(!block.verify_hash());

            block.compute_hash();
            block.verify_hash()
        }

        fn serialize_deserialize(block: StateBlock) -> bool {
            StateBlock::from_bytes(&StateBlock::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap();

            true
        }
    }
}
