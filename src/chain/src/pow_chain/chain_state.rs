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

use crate::chain::ChainErr;
use crate::types::*;
use crate::pow_chain::block::GENESIS_HASH_KEY;
use persistence::PersistentDb;
use crypto::{Hash, NodeId};
use hashbrown::{HashMap, HashSet};
use std::collections::VecDeque;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BlockType {
    Checkpoint,
    Transaction
}

#[derive(Clone, Debug)]
pub struct PowChainState {
    /// Database storing the ledger ephemeral state.
    pub(crate) db: PersistentDb,

    /// The current chain height
    pub(crate) height: u64,

    /// Current difficulty
    pub difficulty: u64,

    /// Current edge bits
    pub(crate) edge_bits: u8,

    /// Which block type is accepted next
    pub(crate) accepts: BlockType,

    /// The current validator's node id. This field
    /// is `None` if we accept checkpoint blocks.
    pub(crate) current_validator: Option<NodeId>,

    /// Number of transaction blocks left that the
    /// current validator is allowed to append. This 
    /// field is `None` if we accept checkpoint blocks.
    pub(crate) txs_blocks_left: Option<u32>,

    /// Root hash of the state trie
    pub(crate) state_root: Hash,

    /// Hash of the last checkpoint block.
    pub last_checkpoint: Hash,
}

impl PowChainState {
    pub fn genesis(db: PersistentDb) -> Self {
        PowChainState {
            db,
            height: 0,
            difficulty: 0,
            edge_bits: miner::MIN_EDGE_BITS,
            accepts: BlockType::Checkpoint, 
            current_validator: None,
            txs_blocks_left: None,
            state_root: Hash::NULL_RLP,
            last_checkpoint: crypto::hash_slice(GENESIS_HASH_KEY),
        }
    }

    pub fn accepts_checkpoint(&self) -> bool {
        self.accepts == BlockType::Checkpoint
    }

    pub fn accepts_tx(&self) -> bool {
        self.accepts == BlockType::Transaction
    }
}

impl Flushable for PowChainState {
    fn flush(&mut self) -> Result<(), ChainErr> {
        self.db.flush();
        Ok(())
    }
}
