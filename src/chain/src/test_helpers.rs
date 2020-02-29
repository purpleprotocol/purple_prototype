/*
  Copyright (C) 2018-2020 The Purple Core Developers.
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

//! Utilities for testing chain modules

use crate::block::Block;
use crate::pow_chain::block::*;
use crate::pow_chain::chain::*;
use crate::pow_chain::PowChainState;
use account::NormalAddress;
use crypto::{Hash, NodeId};
use graphlib::{Graph, VertexId};
use hashbrown::{HashMap, HashSet};
use miner::Proof;
use parking_lot::RwLock;
use rand::prelude::*;
use std::sync::Arc;

pub fn init_test_chains() -> PowChainRef {
    let pow_db = test_helpers::init_tempdb();
    let state_db = test_helpers::init_tempdb();
    let pow_chain = Arc::new(RwLock::new(PowChain::new(
        pow_db,
        PowChainState::genesis(state_db),
        true,
    )));
    let pow_chain_ref = PowChainRef::new(pow_chain);

    pow_chain_ref
}

/// Wrapper struct around a block test set
#[derive(Clone, Debug)]
pub struct BlockTestSet {
    pub pow_graph: Graph<Arc<PowBlock>>,
    pub pow_blocks: Vec<Arc<PowBlock>>,
    pub pow_canonical: Arc<PowBlock>,
}

impl BlockTestSet {
    pub fn new() -> BlockTestSet {
        BlockTestSet {
            pow_graph: Graph::new(),
            pow_blocks: Vec::new(),
            pow_canonical: PowBlock::genesis(),
        }
    }
}
