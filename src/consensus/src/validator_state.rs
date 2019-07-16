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

use crypto::NodeId;
use causality::Stamp;
use hashbrown::HashSet;

#[derive(Clone, Debug)]
pub struct ValidatorState {
    /// Whether or not the validator is allowed
    /// to send an event.
    pub(crate) allowed_to_send: bool,

    /// Number of events sent by different validators
    /// since the last sent block of the validator.
    /// 
    /// This is `None` if the validator has not yet
    /// sent an initial event.
    pub(crate) followers: Option<HashSet<NodeId>>,

    /// The remaining number of allocated events
    /// that the validator is allowed to send during
    /// its lifetime in the pool.
    pub(crate) remaining_events: u64,

    /// The stamp of the latest event that
    /// has been sent by the validator.
    pub(crate) latest_stamp: Stamp,

    /// The index of the validator
    pub(crate) validator_idx: usize,
}

impl ValidatorState {
    pub fn new(
        allowed_to_send: bool, 
        remaining_events: u64, 
        idx: usize, 
        init_stamp: Stamp,
        followers: Option<HashSet<NodeId>>
    ) -> ValidatorState {
        ValidatorState {
            allowed_to_send,
            followers,
            remaining_events,
            latest_stamp: init_stamp,
            validator_idx: idx,
        }
    }
}
