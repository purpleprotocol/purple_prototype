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
use graphlib::{VertexId, Graph};
use hashbrown::HashSet;
use rand::prelude::*;

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

/// Wrapper struct around a block test set
#[derive(Clone, Debug)]
pub struct BlockTestSet {
    pub hard_blocks: Vec<Arc<HardBlock>>,
    pub easy_blocks: Vec<Arc<EasyBlock>>,
    pub state_blocks: Vec<Arc<StateBlock>>,
    pub easy_canonical: Arc<EasyBlock>,
    pub hard_canonical: Arc<HardBlock>,
    pub state_canonical: Arc<StateBlock>,
}

impl BlockTestSet {
    pub fn new() -> BlockTestSet {
        BlockTestSet {
            hard_blocks: Vec::new(),
            easy_blocks: Vec::new(),
            state_blocks: Vec::new(),
            easy_canonical: EasyBlock::genesis(),
            hard_canonical: HardBlock::genesis(),
            state_canonical: StateBlock::genesis(),
        }
    }
}

/// Generates a test set of blocks with the given depth and fork rate. If the 
/// generate byzantine flag is given, byzantine blocks will also be generated.
/// 
/// A fork rate of 10 means that the probability of a fork is 50%. 0 means that
/// the probability is 0%.
pub fn chain_test_set(
    depth: usize, 
    fork_rate: u64, 
    generate_byzantine: bool,
    generate_state: bool
) -> BlockTestSet {
    if depth < 5 {
        panic!("Invalid depth parameter! Minimum is 5.");
    }

    if fork_rate > 10 {
        panic!("Invalid fork rate parameter! Must be a number between 0 and 10.");
    }

    let mut easy_chain_buf: Graph<Arc<EasyBlock>> = Graph::new();
    let mut easy_canonical_tip: Option<VertexId> = None;
    let mut hard_chain_buf: Graph<Arc<HardBlock>> = Graph::new();
    let mut hard_canonical_tip: Option<VertexId> = None;
    let mut state_chain_buf: Graph<Arc<StateBlock>> = Graph::new();
    let mut state_canonical_tip: Option<VertexId> = None;
    let mut cur_hard_height: u64 = 0;
    let mut rng = rand::thread_rng();
        
    // For each iteration, generate one hard block and several easy
    // blocks along with the associated state blocks.
    loop {
        // Stop at desired depth
        if cur_hard_height >= depth as u64 {
            break;
        }

        let easy_blocks_to_generate = rng.gen_range(0, 8);
        let last_hard = if let Some(ref id) = hard_canonical_tip {
            hard_chain_buf.fetch(id).unwrap().clone()
        } else {
            HardBlock::genesis()
        };

        let mut last_easy = if let Some(ref id) = easy_canonical_tip {
            easy_chain_buf.fetch(id).unwrap().clone()
        } else {
            EasyBlock::genesis()
        };

        let mut last_easy_height = last_easy.height() + 1;

        // Generate random amount of easy blocks for this step
        for _ in 0..easy_blocks_to_generate {
            let mut easy_block = EasyBlock::new(
                last_easy.block_hash(), 
                last_hard.block_hash().unwrap(), 
                NormalAddress::random(), 
                crate::random_socket_addr(), 
                last_easy_height, 
                0,
                Proof::test_proof(42),
            );

            easy_block.compute_hash();
            let easy_block = Arc::new(easy_block);

            // Set last easy
            last_easy = easy_block.clone();

            // Append the block to the graph
            let id = easy_chain_buf.add_vertex(easy_block);

            // Add edge between last canonical tip and new one
            if let Some(ref tip_id) = easy_canonical_tip {
                easy_chain_buf.add_edge(tip_id, &id).unwrap();
            }
            
            easy_canonical_tip = Some(id);

            let random_num = rng.gen_range(0, 100);
            let fork_chance = if fork_rate == 0 {
                0
            } else {
                (fork_rate * 100) / 20
            };

            let will_fork = random_num < fork_chance;

            // Generate a fork
            if will_fork {
                let mut easy_block = EasyBlock::new(
                    last_easy.block_hash(), 
                    last_hard.block_hash().unwrap(), 
                    NormalAddress::random(), 
                    crate::random_socket_addr(), 
                    last_easy_height, 
                    0,
                    Proof::test_proof(42),
                );

                easy_block.compute_hash();
                let easy_block = Arc::new(easy_block);

                // Append the block to the graph
                let id = easy_chain_buf.add_vertex(easy_block);

                // Add edge between last canonical tip and new one
                if let Some(ref tip_id) = easy_canonical_tip {
                    easy_chain_buf.add_edge(tip_id, &id).unwrap();
                }

                let random_num = rng.gen_range(0, 100);
                let fork_chance = if fork_rate == 0 {
                    0
                } else {
                    (fork_rate * 100) / 20
                };

                // Fork one of the past tips if this is true
                let will_fork = random_num < fork_chance;

                if will_fork {
                    let tip = easy_chain_buf
                        .tips()
                        .filter(|t| {
                            let tip = easy_chain_buf.fetch(t).unwrap();
                            Some(**t) != easy_canonical_tip && tip.height() < cur_hard_height
                        })
                        .cloned()
                        .choose(&mut rng);

                    // Add block with the tip's parent hash
                    if let Some(ref tip_id) = tip {
                        let tip = easy_chain_buf.fetch(tip_id).unwrap().clone();
                        let mut easy_block = EasyBlock::new(
                            tip.block_hash(), 
                            last_hard.block_hash().unwrap(), 
                            NormalAddress::random(), 
                            crate::random_socket_addr(), 
                            tip.height() + 1, 
                            0,
                            Proof::test_proof(42),
                        );

                        easy_block.compute_hash();
                        let easy_block = Arc::new(easy_block);

                        // Append the block to the graph
                        let id = easy_chain_buf.add_vertex(easy_block);

                        easy_chain_buf.add_edge(tip_id, &id).unwrap();
                    }
                }
            }

            last_easy_height += 1;
        }

        // Generate byzantine easy blocks
        if generate_byzantine {
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

        let last_hard_hash = last_hard.block_hash().unwrap();

        // Generate one new hard block
        let mut hard_block = HardBlock::new(
            Some(last_hard_hash), 
            NormalAddress::random(),
            crate::random_socket_addr(),
            last_hard.height() + 1, 
            0,
            last_easy.block_hash().unwrap(), 
            Proof::test_proof(42),
        );
        hard_block.compute_hash();
        let hard_block = Arc::new(hard_block);

        // Set current height
        cur_hard_height = hard_block.height();

        // Append hard block to the graph
        let id = hard_chain_buf.add_vertex(hard_block);

        // Add edge between last canonical tip and new one
        if let Some(ref tip_id) = hard_canonical_tip {
            hard_chain_buf.add_edge(tip_id, &id).unwrap();
        }

        // Set new hard canonical tip
        hard_canonical_tip = Some(id);

        // Generate byzantine hard block
        if generate_byzantine {
            unimplemented!();
        }

        // Generate state blocks
        if generate_state {
            unimplemented!();
        }
    }

    // Assemble test set
    let mut test_set = BlockTestSet::new();
    let easy_ids: Vec<&VertexId> = easy_chain_buf.vertices().collect();
    let hard_ids: Vec<&VertexId> = hard_chain_buf.vertices().collect();
    let state_ids: Vec<&VertexId> = state_chain_buf.vertices().collect();

    test_set.easy_blocks = easy_ids
        .iter()
        .map(|id| easy_chain_buf.fetch(id).unwrap().clone())
        .collect();

    test_set.hard_blocks = hard_ids
        .iter()
        .map(|id| hard_chain_buf.fetch(id).unwrap().clone())
        .collect();

    test_set.state_blocks = state_ids
        .iter()
        .map(|id| state_chain_buf.fetch(id).unwrap().clone())
        .collect();

    if let Some(ref id) = easy_canonical_tip {
        test_set.easy_canonical = easy_chain_buf.fetch(id).unwrap().clone();
    }

    if let Some(ref id) = hard_canonical_tip {
        test_set.hard_canonical = hard_chain_buf.fetch(id).unwrap().clone();
    }

    if let Some(ref id) = state_canonical_tip {
        test_set.state_canonical = state_chain_buf.fetch(id).unwrap().clone();
    }

    // The hard test set must have at least one block
    // which follows the genesis block.
    assert!(test_set.hard_blocks.iter().any(|b| b.parent_hash().unwrap() == HardBlock::genesis().block_hash().unwrap()));

    test_set
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