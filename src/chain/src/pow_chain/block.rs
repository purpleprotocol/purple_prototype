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

use crate::block::Block;
use crate::chain::*;
use crate::types::*;
use crate::pow_chain::checkpoint_block::CheckpointBlock;
use crate::pow_chain::transaction_block::TransactionBlock;
use crate::pow_chain::PowChainState;
use crypto::Hash;
use chrono::prelude::*;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum PowBlock {
    Genesis,
    Checkpoint(Arc<CheckpointBlock>),
    Transaction(Arc<TransactionBlock>),
}

impl PartialEq for PowBlock {
    fn eq(&self, other: &PowBlock) -> bool {
        // This only makes sense when the block is received
        // when the node is a server i.e. when the block is
        // guaranteed to have a hash because it already passed
        // the parsing stage.
        self.block_hash().unwrap() == other.block_hash().unwrap()
    }
}

impl Eq for PowBlock {}

impl HashTrait for PowBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_hash().unwrap().hash(state);
    }
}

impl Block for PowBlock {
    type ChainState = PowChainState;

    fn genesis() -> Arc<PowBlock> {
        Arc::new(PowBlock::Genesis)
    }

    fn is_genesis(&self) -> bool {
        *self == PowBlock::Genesis
    }

    fn genesis_state() -> Self::ChainState {
        unimplemented!();
    }

    fn block_hash(&self) -> Option<Hash> {
        match *self {
            PowBlock::Genesis => {
                Some(crypto::hash_slice(b"GENESIS"))
            }

            PowBlock::Checkpoint(ref block) => {
                block.block_hash()
            }

            PowBlock::Transaction(ref block) => {
                block.block_hash()
            }
        }
    }

    fn parent_hash(&self) -> Option<Hash> {
        match *self {
            PowBlock::Genesis => {
                None
            }

            PowBlock::Checkpoint(ref block) => {
                block.parent_hash()
            }

            PowBlock::Transaction(ref block) => {
                block.parent_hash()
            }
        }
    }

    fn timestamp(&self) -> DateTime<Utc> {
        match *self {
            PowBlock::Genesis => {
                unimplemented!();
            }

            PowBlock::Checkpoint(ref block) => {
                block.timestamp()
            }

            PowBlock::Transaction(ref block) => {
                block.timestamp()
            }
        }
    }

    fn height(&self) -> u64 {
        match *self {
            PowBlock::Genesis => {
                0
            }

            PowBlock::Checkpoint(ref block) => {
                block.height()
            }

            PowBlock::Transaction(ref block) => {
                block.height()
            }
        }
    }

    fn after_write() -> Option<Box<dyn FnMut(Arc<PowBlock>)>> {
        let fun = |block: Arc<PowBlock>| {
            match *block {
                PowBlock::Genesis => { }

                PowBlock::Checkpoint(ref block) => {
                    if let Some(mut closure) = CheckpointBlock::after_write() {
                        closure(block.clone()) 
                    }
                }

                PowBlock::Transaction(ref block) => {
                    if let Some(mut closure) = TransactionBlock::after_write() {
                        closure(block.clone()) 
                    }
                }
            }
        };

        Some(Box::new(fun))
    }

    fn append_condition(block: Arc<Self>, chain_state: Self::ChainState, branch_type: BranchType) -> Result<Self::ChainState, ChainErr> {
        match *block {
            PowBlock::Genesis => { 
                unimplemented!();
            }

            PowBlock::Checkpoint(ref block) => {
                CheckpointBlock::append_condition(block.clone(), chain_state, branch_type)
            }

            PowBlock::Transaction(ref block) => {
                TransactionBlock::append_condition(block.clone(), chain_state, branch_type)
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match *self {
            PowBlock::Genesis => {
                Vec::new()
            }

            PowBlock::Checkpoint(ref block) => {
                block.to_bytes()
            }

            PowBlock::Transaction(ref block) => {
                block.to_bytes()
            }
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<PowBlock>, &'static str> {
        if bytes.len() == 0 {
            return Err("Cannot receive empty byte buffer!");
        }

        match bytes[0] {
            CheckpointBlock::BLOCK_TYPE => {
                let block = CheckpointBlock::from_bytes(bytes)?;
                Ok(Arc::new(PowBlock::Checkpoint(block))) // TODO: Make this less ugly
            }

            TransactionBlock::BLOCK_TYPE => {
                let block = TransactionBlock::from_bytes(bytes)?;
                Ok(Arc::new(PowBlock::Transaction(block))) // TODO: Make this less ugly
            }

            _ => {
                Err("Invalid block type!")
            }
        }
    }
}

use quickcheck::*;
use rand::prelude::*;

impl Arbitrary for PowBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> PowBlock {
        let rand_num: u8 = rand::thread_rng().gen_range(0, 2);

        match rand_num {
            0 => PowBlock::Checkpoint(Arbitrary::arbitrary(g)),
            1 => PowBlock::Transaction(Arbitrary::arbitrary(g)),
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn chain_integration() {

    // }

    quickcheck! {
        fn serialize_deserialize(block: CheckpointBlock) -> bool {
            PowBlock::from_bytes(&PowBlock::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap();

            true
        }
    }
}