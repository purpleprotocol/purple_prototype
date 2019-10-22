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
use crate::pow_chain::block::PENDING_VAL_BUF_SIZE;
use crate::pow_chain::epoch_info::EpochInfo;
use crate::pow_chain::validator_entry::ValidatorEntry;
use crypto::NodeId;
use hashbrown::{HashMap, HashSet};
use std::collections::VecDeque;
use std::net::SocketAddr;

// /// How many epochs to keep in the backlog
// pub const EPOCH_BACKLOG_SIZE: usize = 10;

#[derive(Clone, PartialEq, Debug)]
/// Chain state associated with proof-of-work chains.
/// This is used to calculate the difficulty on the `PowChain`.
pub struct PowChainState {
    /// The current chain height
    pub(crate) height: u64,

    /// Current difficulty
    pub(crate) difficulty: u64,

    /// Current edge bits
    pub(crate) edge_bits: u8,

    /// If existing, this denotes the first epoch that will be 
    /// able to have an active validator set. This is `None` if
    /// there is an active validator set.
    pub(crate) first_start_epoch: Option<u64>,

    /// This denotes the first epoch where a validator will be 
    /// leaving the active validator set. This is `None` if there
    /// is no current active validator set.
    pub(crate) first_end_epoch: Option<u64>,

    /// This denotes the last epoch which will have an active
    /// validator set with this configuration. This is `None` if there
    /// is no current active validator set.
    pub(crate) last_end_epoch: Option<u64>,

    /// Stack containing buffered validator ids that are 
    /// currently awaiting to join the validator pool.
    pub(crate) pending_validators: Vec<NodeId>,

    // /// Backlog containing the information of the latest 10 epochs.
    // pub(crate) epoch_backlog: VecDeque<EpochInfo>,

    /// Lookup table between node ids and active validator entries.
    pub(crate) active_validator_lookup: HashMap<NodeId, ValidatorEntry>,

    /// Lookup table between node ids and pending validator entries.
    pub(crate) pending_validator_lookup: HashMap<NodeId, ValidatorEntry>,

    /// Set containing ips of active validators. Used for validation.
    pub(crate) active_validator_ips: HashSet<SocketAddr>,

    /// Set containing ips of pending validators. Used for validation.
    pub(crate) pending_validator_ips: HashSet<SocketAddr>,

    /// Mapping between epochs and node ids who should join in those epochs.
    pub(crate) start_epochs_mapping: HashMap<u64, HashSet<NodeId>>,

    /// Mapping between epochs and node ids who should leave in those epochs.
    pub(crate) end_epochs_mapping: HashMap<u64, HashSet<NodeId>>,
}

impl PowChainState {
    pub fn genesis() -> Self {
        PowChainState {
            height: 0,
            difficulty: 0,
            edge_bits: miner::MIN_EDGE_BITS,
            first_start_epoch: Some(PENDING_VAL_BUF_SIZE),
            first_end_epoch: None,
            last_end_epoch: None,
            pending_validators: Vec::new(),
            //epoch_backlog: VecDeque::with_capacity(EPOCH_BACKLOG_SIZE),
            active_validator_lookup: HashMap::new(),
            pending_validator_lookup: HashMap::new(),
            active_validator_ips: HashSet::new(),
            pending_validator_ips: HashSet::new(),
            start_epochs_mapping: HashMap::new(),
            end_epochs_mapping: HashMap::new(),
        }
    }

    /// Returns the number of active validators
    pub fn active_validator_count(&self) -> u64 {
        self.active_validator_lookup.len() as u64
    }

    /// Returns the number of validators that are still
    /// waiting to join an active validator pool.
    pub fn pending_validator_count(&self) -> u64 {
        self.pending_validator_lookup.len() as u64
    }
}

impl Flushable for PowChainState {
    fn flush(&mut self) -> Result<(), ChainErr> {
        Ok(())
    }
}
