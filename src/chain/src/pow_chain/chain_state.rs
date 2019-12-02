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
use crypto::{Hash, NodeId};
use hashbrown::{HashMap, HashSet};
use std::collections::VecDeque;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BlockType {
    Checkpoint,
    Transaction
}

#[derive(Clone, PartialEq, Debug)]
pub struct PowChainState {
    /// The current chain height
    pub(crate) height: u64,

    /// Current difficulty
    pub(crate) difficulty: u64,

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
}

impl PowChainState {
    pub fn genesis() -> Self {
        PowChainState {
            height: 0,
            difficulty: 0,
            edge_bits: miner::MIN_EDGE_BITS,
            accepts: BlockType::Checkpoint, 
            current_validator: None,
            txs_blocks_left: None,
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
        Ok(())
    }
}
