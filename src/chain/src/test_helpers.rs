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

use crate::block::Block;
use crate::hard_chain::chain::*;
use crate::hard_chain::state::*;
use crate::hard_chain::block::*;
use crate::easy_chain::chain::*;
use crate::easy_chain::block::*;
use crate::state_chain::chain::*;
use crate::state_chain::state::*;
use crate::state_chain::block::*;
use crate::pow_chain_state::PowChainState;
use account::NormalAddress;
use miner::Proof;
use parking_lot::RwLock;
use std::sync::Arc;
use rand::Rng;

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

/// Utility class for generating blocks for testing. Use this in 
/// tandem with a pair of initialized chains.
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
        let easy_chain = self.easy_chain_ref.chain.read();
        let hard_chain = self.hard_chain_ref.chain.read();

        let easy_canonical = easy_chain.canonical_tip();
        let hard_canonical = hard_chain.canonical_tip();
        let hard_hash = hard_canonical.block_hash().unwrap();

        let mut easy_block = EasyBlock::new(
            easy_canonical.block_hash(), 
            hard_hash, 
            NormalAddress::random(), 
            crate::random_socket_addr(), 
            easy_canonical.height() + 1, 
            0,
            Proof::test_proof(42),
        );

        easy_block.compute_hash();
        Some(Arc::new(easy_block))
    }

    /// Returns a generated valid hard block if possible.
    pub fn next_valid_hard(&self) -> Option<Arc<HardBlock>> {
        let easy_chain = self.easy_chain_ref.chain.read();
        let hard_chain = self.hard_chain_ref.chain.read();

        let easy_canonical = easy_chain.canonical_tip();
        let hard_canonical = hard_chain.canonical_tip();
        let easy_hash = easy_canonical.block_hash().unwrap();

        let mut hard_block = HardBlock::new(
            hard_canonical.block_hash(), 
            NormalAddress::random(),
            crate::random_socket_addr(),
            hard_canonical.height() + 1, 
            0,
            easy_hash, 
            Proof::test_proof(42),
        );

        hard_block.compute_hash();
        Some(Arc::new(hard_block))
    }

    /// Returns a generated valid state block if possible.
    pub fn next_valid_state(&self) -> Option<Arc<EasyBlock>> {
        unimplemented!();
    }

    /// Returns a generated invalid easy block if possible.
    pub fn next_invalid_easy(&self) -> Option<Arc<EasyBlock>> {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);
        let byzantine_action = match random {
            0 => EasyByzantineActions::HardHashWithLowerHeight,
            1 => EasyByzantineActions::InvalidHardParentHash,
            _ => panic!(),
        };

        match byzantine_action {
            EasyByzantineActions::HardHashWithLowerHeight => {
                unimplemented!();
            }

            EasyByzantineActions::InvalidHardParentHash => {
                unimplemented!();
            }
        }
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

/// Enum representing byzantine actions that
/// are performed on the easy chain.
/// 
/// TODO: Add as many actions as possible
#[derive(Debug, Clone, PartialEq)]
enum EasyByzantineActions {
    /// A byzantine action consisting of sending
    /// a valid hard block but with a referenced
    /// easy block that has a lower height than 
    /// the last referenced block.
    HardHashWithLowerHeight,

    /// A byzantine action consisting of sending
    /// a block that has all the correct fields 
    /// except the referenced hard block having
    /// an invalid parent hash.
    InvalidHardParentHash,
}