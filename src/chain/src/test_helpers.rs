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

//! Utilities for testing chain modules

use crate::hard_chain::chain::*;
use crate::hard_chain::state::*;
use crate::hard_chain::block::*;
use crate::easy_chain::chain::*;
use crate::easy_chain::block::*;
use crate::state_chain::chain::*;
use crate::state_chain::state::*;
use crate::state_chain::block::*;
use crate::pow_chain_state::PowChainState;
use parking_lot::RwLock;
use std::sync::Arc;

pub fn init_test_chains() -> (EasyChainRef, HardChainRef, StateChainRef) {
    let easy_db = test_helpers::init_tempdb();
    let hard_db = test_helpers::init_tempdb();
    let state_db = test_helpers::init_tempdb();
    let state_storage_db = test_helpers::init_tempdb();
    let easy_chain = Arc::new(RwLock::new(EasyChain::new(easy_db, PowChainState::genesis(), true)));
    let easy_chain_ref = EasyChainRef::new(easy_chain);
    let hard_chain = Arc::new(RwLock::new(HardChain::new(hard_db, HardChainState::genesis_init(easy_chain_ref.clone()), true)));
    let hard_chain_ref = HardChainRef::new(hard_chain);
    let state_chain = Arc::new(RwLock::new(StateChain::new(state_db, ChainState::new(state_storage_db), true))); // TODO: Replace this with genesis state
    let state_chain_ref = StateChainRef::new(state_chain);

    (easy_chain_ref, hard_chain_ref, state_chain_ref)
}

/// Utility class for generating blocks for testing
pub struct BlockGenerator {
    easy_chain_ref: EasyChainRef,
    hard_chain_ref: HardChainRef,
    state_chain_ref: StateChainRef,
}

impl BlockGenerator {
    pub fn new(
        easy_chain_ref: EasyChainRef,
        hard_chain_ref: HardChainRef,
        state_chain_ref: StateChainRef,
    ) -> BlockGenerator {
        BlockGenerator {
            easy_chain_ref,
            hard_chain_ref,
            state_chain_ref,
        }
    }

    /// Returns a generated valid easy block if possible.
    pub fn next_valid_easy(&self) -> Option<Arc<EasyBlock>> {
        unimplemented!();
    }

    /// Returns a generated valid hard block if possible.
    pub fn next_valid_hard(&self) -> Option<Arc<HardBlock>> {
        unimplemented!();
    }

    /// Returns a generated valid state block if possible.
    pub fn next_valid_state(&self) -> Option<Arc<EasyBlock>> {
        unimplemented!();
    }

    /// Returns a generated invalid easy block if possible.
    pub fn next_invalid_easy(&self) -> Option<Arc<EasyBlock>> {
        unimplemented!();
    }

    /// Returns a generated invalid hard block if possible.
    pub fn next_invalid_hard(&self) -> Option<Arc<HardBlock>> {
        unimplemented!();
    }

    /// Returns a generated invalid state block if possible.
    pub fn next_invalid_state(&self) -> Option<Arc<EasyBlock>> {
        unimplemented!();
    }
}