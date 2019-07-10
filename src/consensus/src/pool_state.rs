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

use crate::validator_state::ValidatorState;
use crypto::NodeId;
use causality::Stamp;
use hashbrown::HashMap;

/// Validator pool state
#[derive(Clone, Debug)]
pub struct PoolState {
    /// Number denoting the current consensus epoch.
    /// This is incremented each time a validator set
    /// is joined to the pool.
    pub epoch: u64,

    /// Remaining number of blocks that the pool is allowed
    /// to produce during the current epoch.
    pub remaining_blocks: u64,

    /// Mapping between validator nodes ids and their state.
    pub validators: HashMap<NodeId, ValidatorState>,
}

impl PoolState {
    pub fn new(epoch: u64, remaining_blocks: u64) -> Self {
        Self {
            epoch,
            remaining_blocks,
            validators: HashMap::new()
        }
    }

    /// Performs an injection of new validators and allocated
    /// blocks that the whole pool can produce. Note that this
    /// function does not check for duplicate node ids.
    pub fn inject(&mut self, validator_set: &HashMap<NodeId, u64>, allocated: u64) {
        let mut fork_stack: Vec<(Stamp, Option<NodeId>)> = vec![(Stamp::seed(), None)];
        let mut forked = vec![];

        // On each injection/epoch change we re-assign
        // the nodes internal ids on an injection.
        let mut all_node_ids: Vec<NodeId> = validator_set
            .keys()
            .chain(self.validators.keys())
            .cloned()
            .collect();

        // Sort ids lexicographically so that injections are deterministic.
        all_node_ids.sort_unstable();

        let mut idx: usize = 0;

        // For each node id, fork a stamp and insert it to
        // the validator pool.
        while let Some(node_id) = all_node_ids.pop() {
            loop {
                if let Some((next_fork, from)) = fork_stack.pop() {
                    let allocated = validator_set.get(&node_id).unwrap();
                    let mut stamp = Stamp::seed();

                    // Update the information of the forked
                    // node if there is any.
                    if let Some(from) = from {
                        let (l, r) = next_fork.fork();

                        // Assign stamps to nodes
                        forked.push((l.clone(), Some(from.clone())));
                        forked.push((r.clone(), Some(node_id.clone())));

                        stamp = r;

                        // Replace stamp of forked node
                        let from_state = self.validators.get_mut(&from).unwrap();
                        from_state.latest_stamp = l;
                    } else {
                        forked.push((next_fork.clone(), Some(node_id.clone())));
                        stamp = next_fork;
                    }

                    // Fetch or create the validator state
                    let validator_state =
                        if let Some(state) = self.validators.get_mut(&node_id) {
                            state
                        } else {
                            self.validators.insert(
                                node_id.clone(),
                                ValidatorState::new(true, allocated.clone(), idx, Stamp::seed()),
                            );
                            self.validators.get_mut(&node_id).unwrap()
                        };

                    // Update the stamp of the validator state
                    validator_state.allowed_to_send = true;
                    validator_state.latest_stamp = stamp;
                    idx += 1;

                    break;
                } else {
                    // Re-fill the fork stack with the forked stamps
                    fork_stack = forked;
                    forked = vec![];
                }
            }
        }

        // Go to next epoch
        self.epoch += 1;

        // Inject allocated events
        self.remaining_blocks = allocated;
    }
}