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
use crate::error::ConsensusErr;
use crate::parameters::*;
use crypto::NodeId;
use causality::Stamp;
use hashbrown::{HashSet, HashMap};

/// Validator pool state
#[derive(Clone, Debug)]
pub struct PoolState {
    /// Number denoting the current consensus epoch.
    /// This is incremented each time a validator set
    /// is joined to the pool.
    pub epoch: u64,

    /// Remaining number of events that the pool is allowed
    /// to produce during the current epoch.
    pub remaining_events: u64,

    /// Mapping between validator nodes ids and their state.
    pub validators: HashMap<NodeId, ValidatorState>,
}

impl PoolState {
    pub fn new(epoch: u64, remaining_events: u64) -> Self {
        Self {
            epoch,
            remaining_events,
            validators: HashMap::new()
        }
    }

    /// Accounts in the pool state that a block has been
    /// sent by the validator with the given id.
    pub fn account_sent_by_validator(&mut self, node_id: &NodeId) -> Result<(), ConsensusErr> {
        let validators_len = self.validators.len();
        
        if let Some(state) = self.validators.get_mut(node_id) {
            if state.allowed_to_send {
                if self.remaining_events > 0 {
                    if state.remaining_events > 0 {
                        self.remaining_events -= 1;
                        state.remaining_events -= 1;
                        state.allowed_to_send = false;
                        state.followers = Some(HashSet::new());
                    } else {
                        return Err(ConsensusErr::NoMoreEvents);
                    }
                } else {
                    return Err(ConsensusErr::NoMoreEventsPool);
                }
            } else {
                return Err(ConsensusErr::NotAllowedToSend);
            }
        } else {
            return Err(ConsensusErr::NoValidatorWithId);
        }

        let other_validators = self.validators
            .iter_mut()
            .filter(|(id, _)| *id != node_id);

        // Update the states of the other validators i.e.
        // increment the number of events sent and possibly
        // allow them to send an event.
        for (_, state) in other_validators {
            if let Some(ref mut followers) = state.followers {
                followers.insert(node_id.clone());

                // Mark validator as being allowed to send
                // if it has met the required follower amount.
                if followers.len() >= heartbeat_requirement(validators_len as u16) as usize {
                    state.allowed_to_send = true;
                }
            } else {
                let mut followers = HashSet::new();
                followers.insert(node_id.clone());

                // Mark validator as being allowed to send
                // if it has met the required follower amount.
                if followers.len() >= heartbeat_requirement(validators_len as u16) as usize {
                    state.allowed_to_send = true;
                }

                state.followers = Some(followers);
            }
        }

        Ok(())
    }

    /// Performs an injection of new validators and allocated
    /// events that the whole pool can produce. 
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

        let mut idx: usize = if all_node_ids.len() > 0 {
            all_node_ids.len() - 1
        } else {
            0
        };

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
                                ValidatorState::new(true, allocated.clone(), idx, Stamp::seed(), None),
                            );
                            self.validators.get_mut(&node_id).unwrap()
                        };

                    // Update the stamp of the validator state
                    validator_state.allowed_to_send = true;
                    validator_state.latest_stamp = stamp;

                    if idx > 0 {
                        idx -= 1;
                    }

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
        self.remaining_events = allocated;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_accounts_sent_by_validator() {
        let mut node_ids: Vec<NodeId> = (0..10)
            .into_iter()
            .map(|_| {
                let (pk, _) = crypto::gen_keypair();
                NodeId::from_pkey(pk)
            })
            .collect();

        node_ids.sort_unstable();
        
        let ids_hm = node_ids
            .iter()
            .cloned()
            .map(|id| (id, 500))
            .collect();

        let mut pool_state = PoolState::new(0, 1000);
        pool_state.inject(&ids_hm, 500);

        // Account for first four nodes
        for i in 0..4 {
            pool_state.account_sent_by_validator(&node_ids[i]).unwrap();
        }

        assert!(pool_state.validators.get(&node_ids[0]).unwrap().allowed_to_send);
        assert!(!pool_state.validators.get(&node_ids[1]).unwrap().allowed_to_send);
        assert!(!pool_state.validators.get(&node_ids[2]).unwrap().allowed_to_send);
        assert!(!pool_state.validators.get(&node_ids[3]).unwrap().allowed_to_send);

        assert_eq!(pool_state.validators.get(&node_ids[0]).unwrap().followers.as_ref().unwrap(), &set![node_ids[1].clone(), node_ids[2].clone(), node_ids[3].clone()]);
        assert_eq!(pool_state.validators.get(&node_ids[1]).unwrap().followers.as_ref().unwrap(), &set![node_ids[2].clone(), node_ids[3].clone()]);
        assert_eq!(pool_state.validators.get(&node_ids[2]).unwrap().followers.as_ref().unwrap(), &set![node_ids[3].clone()]);
        assert_eq!(pool_state.validators.get(&node_ids[3]).unwrap().followers.as_ref().unwrap(), &HashSet::new());

        pool_state.account_sent_by_validator(&node_ids[0]).unwrap();
        assert_eq!(pool_state.validators.get(&node_ids[0]).unwrap().followers.as_ref().unwrap(), &HashSet::new());
        assert_eq!(pool_state.validators.get(&node_ids[1]).unwrap().followers.as_ref().unwrap(), &set![node_ids[0].clone(), node_ids[2].clone(), node_ids[3].clone()]);
        assert_eq!(pool_state.validators.get(&node_ids[2]).unwrap().followers.as_ref().unwrap(), &set![node_ids[0].clone(), node_ids[3].clone()]);
        assert_eq!(pool_state.validators.get(&node_ids[3]).unwrap().followers.as_ref().unwrap(), &set![node_ids[0].clone()]);

        pool_state.account_sent_by_validator(&node_ids[1]).unwrap();
        pool_state.account_sent_by_validator(&node_ids[4]).unwrap();
        pool_state.account_sent_by_validator(&node_ids[5]).unwrap();
        pool_state.account_sent_by_validator(&node_ids[3]).unwrap();
        pool_state.account_sent_by_validator(&node_ids[0]).unwrap();
        pool_state.account_sent_by_validator(&node_ids[4]).unwrap();
    }

    #[test]
    fn it_fails_when_accounting_for_non_existing_id() {
        let non_belonging_id = {
            let (pk, _) = crypto::gen_keypair();
            NodeId::from_pkey(pk)
        }; 

        let mut node_ids: Vec<NodeId> = (0..10)
            .into_iter()
            .map(|_| {
                let (pk, _) = crypto::gen_keypair();
                NodeId::from_pkey(pk)
            })
            .collect();

        node_ids.sort_unstable();
        
        let ids_hm = node_ids
            .iter()
            .cloned()
            .map(|id| (id, 500))
            .collect();

        let mut pool_state = PoolState::new(0, 1000);
        pool_state.inject(&ids_hm, 500);

        assert_eq!(pool_state.account_sent_by_validator(&non_belonging_id), Err(ConsensusErr::NoValidatorWithId));
    }

    #[test]
    fn it_fails_when_accounting_for_node_that_already_sent() {
        let mut node_ids: Vec<NodeId> = (0..10)
            .into_iter()
            .map(|_| {
                let (pk, _) = crypto::gen_keypair();
                NodeId::from_pkey(pk)
            })
            .collect();

        node_ids.sort_unstable();
        
        let ids_hm = node_ids
            .iter()
            .cloned()
            .map(|id| (id, 500))
            .collect();

        let mut pool_state = PoolState::new(0, 1000);
        pool_state.inject(&ids_hm, 500);

        // Account for first four nodes
        for i in 0..3 {
            pool_state.account_sent_by_validator(&node_ids[i]).unwrap();
        }

        assert_eq!(pool_state.account_sent_by_validator(&node_ids[2]), Err(ConsensusErr::NotAllowedToSend));
    }

    #[test]
    fn it_fails_when_there_are_no_more_allocated_events() {
        let mut node_ids: Vec<NodeId> = (0..10)
            .into_iter()
            .map(|_| {
                let (pk, _) = crypto::gen_keypair();
                NodeId::from_pkey(pk)
            })
            .collect();

        node_ids.sort_unstable();
        
        let ids_hm = node_ids
            .iter()
            .cloned()
            .map(|id| (id, 1))
            .collect();

        let mut pool_state = PoolState::new(0, 500);
        pool_state.inject(&ids_hm, 500);

        // Account for first four nodes
        for i in 0..4 {
            pool_state.account_sent_by_validator(&node_ids[i]).unwrap();
        }

        assert_eq!(pool_state.account_sent_by_validator(&node_ids[0]), Err(ConsensusErr::NoMoreEvents));
    }

    #[test]
    fn it_fails_when_there_are_no_more_allocated_events_pool() {
        let mut node_ids: Vec<NodeId> = (0..10)
            .into_iter()
            .map(|_| {
                let (pk, _) = crypto::gen_keypair();
                NodeId::from_pkey(pk)
            })
            .collect();

        node_ids.sort_unstable();
        
        let ids_hm = node_ids
            .iter()
            .cloned()
            .map(|id| (id, 500))
            .collect();

        let mut pool_state = PoolState::new(0, 0);
        pool_state.inject(&ids_hm, 2);

        pool_state.account_sent_by_validator(&node_ids[0]).unwrap();
        pool_state.account_sent_by_validator(&node_ids[1]).unwrap();

        assert_eq!(pool_state.account_sent_by_validator(&node_ids[2]), Err(ConsensusErr::NoMoreEventsPool));
    }

    #[test]
    fn it_assigns_correct_indexes() {
        let mut node_ids: Vec<NodeId> = (0..10)
            .into_iter()
            .map(|_| {
                let (pk, _) = crypto::gen_keypair();
                NodeId::from_pkey(pk)
            })
            .collect();

        node_ids.sort_unstable();
        
        let ids_hm = node_ids
            .iter()
            .cloned()
            .map(|id| (id, 500))
            .collect();

        let mut pool_state = PoolState::new(0, 1000);
        pool_state.inject(&ids_hm, 500);

        assert_eq!(pool_state.validators.get(&node_ids[0]).unwrap().validator_idx, 0);
        assert_eq!(pool_state.validators.get(&node_ids[1]).unwrap().validator_idx, 1);
        assert_eq!(pool_state.validators.get(&node_ids[2]).unwrap().validator_idx, 2);
        assert_eq!(pool_state.validators.get(&node_ids[3]).unwrap().validator_idx, 3);
        assert_eq!(pool_state.validators.get(&node_ids[4]).unwrap().validator_idx, 4);
        assert_eq!(pool_state.validators.get(&node_ids[5]).unwrap().validator_idx, 5);
        assert_eq!(pool_state.validators.get(&node_ids[6]).unwrap().validator_idx, 6);
        assert_eq!(pool_state.validators.get(&node_ids[7]).unwrap().validator_idx, 7);
        assert_eq!(pool_state.validators.get(&node_ids[8]).unwrap().validator_idx, 8);
        assert_eq!(pool_state.validators.get(&node_ids[9]).unwrap().validator_idx, 9);
    }
}