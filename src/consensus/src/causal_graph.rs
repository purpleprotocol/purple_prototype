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

use crate::candidate::Candidate;
use crate::parameters::*;
use crate::validation::ValidationResp;
use crate::validator_state::ValidatorState;
use causality::Stamp;
use crypto::Hash;
use events::Event;
use graphlib::{Graph, VertexId};
use hashbrown::{HashMap, HashSet};
use network::NodeId;
use std::collections::VecDeque;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct CausalGraph {
    /// Graph structure holding the causal graph
    pub graph: Graph<Arc<Event>>,

    /// Our node's id
    node_id: NodeId,

    /// Events that do not yet directly follow
    /// other events from the causal graph.
    pending: HashSet<VertexId>,

    /// A mapping between events that follow other events
    /// but do not have any follower and the number of
    /// followed events.
    ends: HashMap<VertexId, usize>,

    /// Mapping between event hashes and vertex ids.
    lookup_table: HashMap<Hash, VertexId>,

    /// The current highest events in the graph and
    /// the number of events that it follows.
    highest: (Vec<Arc<Event>>, usize),

    /// The current highest following events of our latest
    /// event in the graph and the number of events that it
    /// follows.
    highest_following: (Vec<Arc<Event>>, usize),

    /// The root event in the causal graph. Note that
    /// the root will always be an event that has
    /// already been ordered by all participants.
    root: Arc<Event>,

    /// Mapping between validator nodes ids and their state.
    validators: HashMap<NodeId, ValidatorState>,

    /// Current candidates
    pub(crate) candidates: HashSet<Candidate>,

    /// Whether the causal graph is in test mode.
    test_mode: bool,
}

impl CausalGraph {
    pub fn new(node_id: NodeId, root_event: Arc<Event>) -> CausalGraph {
        let mut graph = Graph::new();
        let mut lookup_table = HashMap::new();
        let mut ends = HashMap::new();
        let id = graph.add_vertex(root_event.clone());

        lookup_table.insert(root_event.event_hash().unwrap(), id.clone());
        ends.insert(id, 0);

        CausalGraph {
            graph,
            ends,
            node_id,
            lookup_table,
            pending: HashSet::new(),
            candidates: HashSet::new(),
            validators: HashMap::new(),
            root: root_event.clone(),
            highest: (vec![root_event], 0),
            highest_following: (vec![], 0),
            test_mode: false,
        }
    }

    #[cfg(test)]
    pub fn new_with_test_mode(node_id: NodeId, root_event: Arc<Event>) -> CausalGraph {
        let mut graph = Graph::new();
        let mut lookup_table = HashMap::new();
        let mut ends = HashMap::new();
        let id = graph.add_vertex(root_event.clone());

        lookup_table.insert(root_event.event_hash().unwrap(), id.clone());
        ends.insert(id, 0);

        CausalGraph {
            graph,
            ends,
            node_id,
            lookup_table,
            pending: HashSet::new(),
            candidates: HashSet::new(),
            validators: HashMap::new(),
            root: root_event.clone(),
            highest: (vec![root_event], 0),
            highest_following: (vec![], 0),
            test_mode: true,
        }
    }

    pub fn is_valid(&self, event: Arc<Event>) -> ValidationResp {
        // Check validator state
        if let Some(validator_state) = self.validators.get(&event.node_id()) {
            // Check stamp validity, if we cannot determine this,
            // this function will be re-applied when this can be
            // determined i.e. once we have received the parent.
            if let Some(parent_id) = self.lookup_table.get(&event.parent_hash().unwrap()) {
                let parent = self.graph.fetch(parent_id).unwrap();

                // The stamp of the event must be equal
                // to the stamp of the parent + the latest
                // stamp of the validator.
                let oracle = validator_state.latest_stamp.join(parent.stamp()).event();

                if oracle != event.stamp() {
                    return ValidationResp::InvalidStamp;
                }
            } else {
                // The validator is allowed to send an event
                // but we cannot determine its validity.
                if validator_state.allowed_to_send {
                    return ValidationResp::CannotDetermineValidity;
                } else {
                    return ValidationResp::NotAllowedToSend;
                }
            }

            if validator_state.allowed_to_send {
                ValidationResp::Valid
            } else {
                ValidationResp::NotAllowedToSend
            }
        } else {
            ValidationResp::NotValidator
        }
    }

    pub fn contains(&self, event: Arc<Event>) -> bool {
        self.lookup_table
            .get(&event.event_hash().unwrap())
            .is_some()
    }

    pub fn push(&mut self, event: Arc<Event>) -> Vec<Arc<Event>> {
        if event.parent_hash().is_none() {
            panic!("Pushing an event without a parent hash is illegal!");
        }

        if !self.contains(event.clone()) {
            let id = self.graph.add_vertex(event.clone());
            let mut to_advance: Vec<Candidate> = vec![];
            let mut ordered: Vec<Arc<Event>> = vec![];

            self.lookup_table
                .insert(event.event_hash().unwrap(), id.clone());
            self.pending.insert(id);

            let mut ends: VecDeque<(VertexId, usize)> = self
                .ends
                .iter()
                .map(|(v, c)| (v.clone(), c.clone()))
                .collect();

            // Loop graph ends and for each one, try to
            // attach a pending event until either the
            // pending set is empty or until we have
            // traversed each end vertex.
            loop {
                if self.pending.is_empty() {
                    return ordered;
                }

                if let Some((current_end_id, current_following)) = ends.pop_back() {
                    let current_end = self.graph.fetch(&current_end_id).unwrap();
                    let mut to_remove = Vec::with_capacity(self.pending.len());
                    let mut to_add = Vec::with_capacity(self.pending.len());
                    let mut found_match = false;
                    let mut invalid_events: HashMap<Arc<Event>, ValidationResp> =
                        HashMap::with_capacity(self.pending.len());

                    for e in self.pending.iter() {
                        let current = self.graph.fetch(e).unwrap();
                        let val_resp = if self.test_mode {
                            // Events are always valid in test mode
                            ValidationResp::Valid
                        } else {
                            self.is_valid(current.clone())
                        };

                        // Skip invalid events
                        if let ValidationResp::Valid = val_resp {
                            // Add edge if matching child is found
                            if current.parent_hash() == current_end.event_hash() {
                                let new_following = current_following + 1;

                                to_remove.push(e.clone());
                                self.ends.insert(e.clone(), new_following);
                                self.ends.remove(&current_end_id);
                                to_add.push((current_end_id, e.clone()));
                                ends.push_front((*e, new_following));

                                // Cache new highest event if this is the case
                                if new_following > self.highest.1 {
                                    self.highest = (vec![current.clone()], new_following);
                                } else if new_following == self.highest.1 {
                                    let (mut highest, _) = self.highest.clone();
                                    highest.push(current.clone());
                                    self.highest = (highest, new_following);
                                }

                                // Cache new highest following if this is the case
                                if new_following > self.highest_following.1
                                    && current.node_id() != self.node_id
                                {
                                    self.highest_following = (vec![current.clone()], new_following);
                                } else if new_following == self.highest_following.1
                                    && current.node_id() != self.node_id
                                {
                                    let (mut highest, _) = self.highest_following.clone();
                                    highest.push(current.clone());
                                    self.highest_following = (highest, new_following);
                                }

                                found_match = true;
                            }
                        } else {
                            if let ValidationResp::CannotDetermineValidity = val_resp {
                                // Do nothing
                            } else {
                                invalid_events.insert(current.clone(), val_resp);
                            }
                        }
                    }

                    // We begin traversing backwards starting from
                    // the current end if we couldn't find a match.
                    if !found_match {
                        let current_end_in_n: Vec<VertexId> =
                            self.graph.in_neighbors(&current_end_id).cloned().collect();

                        if current_end_in_n.len() > 1 {
                            panic!("A vertex cannot have more than one parent!");
                        }

                        for n in current_end_in_n {
                            ends.push_front((n, current_following - 1));
                        }
                    }

                    // Add invalid events to removal set
                    for (e, _) in invalid_events.iter() {
                        to_remove.push(
                            self.lookup_table
                                .get(&e.event_hash().unwrap())
                                .unwrap()
                                .clone(),
                        );
                    }

                    for e in to_remove.iter() {
                        self.pending.remove(e);
                    }

                    for e in to_add.iter() {
                        self.graph.add_edge(&e.0, &e.1).unwrap();

                        // Don't find candidates in test mode
                        if !self.test_mode {
                            let event = self.graph.fetch(&e.1).unwrap();

                            // Mark as candidate if the event directly
                            // follows the current root event in the graph.
                            if event.parent_hash() == self.root.event_hash() {
                                self.candidates.insert(Candidate::new(event.clone()));
                            } else {
                                // Mapping between candidate refs and their replacements
                                let mut replacements: HashMap<Candidate, Candidate> =
                                    HashMap::with_capacity(self.candidates.len());

                                // Otherwise, we find the candidate which the
                                // event follows and then we update its vote count.
                                for c in self.candidates.iter() {
                                    let not_in_proposal_stage = !c.proposal_stage
                                        && c.event.stamp().happened_before(event.stamp())
                                        && !c.voters_ids.contains(&event.node_id());

                                    let is_in_proposal_stage = c.proposal_stage
                                        && c.event.stamp().happened_before(event.stamp())
                                        && !c.voters_ids.contains(&event.node_id());

                                    // If the candidate is not in the proposal stage,
                                    // we add it to the voters set.
                                    if not_in_proposal_stage {
                                        let candidate_ref = self.candidates.get(&c).unwrap();
                                        let mut candidate = if let Some(replacement) =
                                            replacements.get(candidate_ref)
                                        {
                                            replacement.clone()
                                        } else {
                                            candidate_ref.clone()
                                        };

                                        candidate.votes += 1;
                                        candidate.voters.insert(
                                            event.clone(),
                                            (0, HashSet::with_capacity(self.validators.len())),
                                        );
                                        candidate.voters_ids.insert(event.node_id());

                                        if candidate.votes
                                            >= proposal_requirement(self.validators.len() as u16)
                                        {
                                            // Enter proposal stage
                                            candidate.proposal_stage = true;
                                        }

                                        replacements.insert(candidate_ref.clone(), candidate);
                                        break;
                                    } else if is_in_proposal_stage {
                                        let mut to_remove: Vec<Arc<Event>> = vec![];
                                        let candidate_ref = self.candidates.get(&c).unwrap();
                                        let mut candidate = if let Some(replacement) =
                                            replacements.get(candidate_ref)
                                        {
                                            replacement.clone()
                                        } else {
                                            candidate_ref.clone()
                                        };

                                        // Traverse voters and check if the event votes for any.
                                        for (e, (vote_count, voters)) in candidate.voters.iter_mut()
                                        {
                                            if e.stamp().happened_before(event.stamp())
                                                && !voters.contains(&event.node_id())
                                            {
                                                *vote_count += 1;
                                                voters.insert(event.node_id());

                                                // If the event can propose, we increment the proposal count
                                                // and remove it from the voters set.
                                                if *vote_count
                                                    >= proposal_requirement(
                                                        self.validators.len() as u16
                                                    )
                                                {
                                                    candidate.proposals += 1;
                                                    to_remove.push(event.clone());
                                                }

                                                break;
                                            }
                                        }

                                        for e in to_remove.iter() {
                                            candidate.voters.remove(e);
                                        }

                                        replacements.insert(candidate_ref.clone(), candidate);

                                        // The candidate can be advanced into the total order
                                        if c.proposals
                                            >= required_proposals(self.validators.len() as u16)
                                        {
                                            to_advance.push(c.clone());
                                        }
                                    }
                                }

                                // Apply replacements
                                for (old, new) in replacements {
                                    self.candidates.remove(&old);
                                    self.candidates.insert(new);
                                }
                            }
                        }
                    }

                    // Don't advance events in test mode
                    if !self.test_mode {
                        // Remove candidates which have been chosen for advancement
                        for c in to_advance.iter() {
                            self.candidates.remove(c);
                            ordered.push(c.event.clone());

                            let candidate_id = self
                                .lookup_table
                                .get(&c.event.event_hash().unwrap())
                                .unwrap();

                            // Update graph
                            self.graph.remove(&candidate_id);

                            // Retain only events that happened after the ordered event
                            let mut ids_to_remove = HashSet::with_capacity(self.pending.len());

                            for p in self.pending.iter() {
                                let pending = self.graph.fetch(p).unwrap();

                                if !pending.stamp().happened_after(c.event.stamp()) {
                                    ids_to_remove.insert(p.clone());
                                }
                            }

                            self.pending.retain(|e| !ids_to_remove.contains(e));
                            self.graph
                                .retain(|e| e.stamp().happened_after(c.event.stamp()));
                            self.ends.retain(|id, _| !ids_to_remove.contains(id));

                            // Set new root as being the ordered event
                            self.root = c.event.clone();
                        }
                    }
                } else {
                    return ordered;
                }
            }
        } else {
            panic!("Cannot push an already contained event!");
        }
    }

    pub(crate) fn highest(&self) -> Arc<Event> {
        let (highest, _) = &self.highest;

        if highest.len() == 1 {
            highest[0].clone()
        } else {
            // Pick one of the highest events at random
            // TODO: Use a deterministic random function here:
            // drf(&highest)

            highest[0].clone()
        }
    }

    pub(crate) fn highest_exclusive(&self, node_id: &NodeId) -> Option<Arc<Event>> {
        let (highest, _) = &self.highest;

        let highest = if highest.len() == 1 {
            highest[0].clone()
        } else {
            // Pick one of the highest events at random
            // TODO: Use a deterministic random function here:
            // drf(&highest)
            highest[0].clone()
        };

        if highest.node_id() != *node_id {
            return Some(highest);
        }

        if highest.parent_hash().is_none() {
            None
        } else {
            let id = self
                .lookup_table
                .get(&highest.parent_hash().unwrap())
                .unwrap();

            let event = self.graph.fetch(id).unwrap();

            if event.node_id() == *node_id {
                panic!("An event cannot follow another event that is owned by the same entity!");
            }

            Some(event.clone())
        }
    }

    pub(crate) fn highest_following(&self) -> Option<Arc<Event>> {
        let (highest_following, _) = &self.highest_following;

        if highest_following.is_empty() {
            None
        } else if highest_following.len() == 1 {
            Some(highest_following[0].clone())
        } else {
            // Pick one of the highest following events at random
            // TODO: Use a deterministic random function here:
            // Some(drf(&highest_following))

            Some(highest_following[0].clone())
        }
    }

    pub(crate) fn compute_highest_following(
        &self,
        node_id: &NodeId,
        event: Arc<Event>,
    ) -> Option<Arc<Event>> {
        let v_id = self.lookup_table.get(&event.event_hash().unwrap());

        if let Some(v_id) = v_id {
            // The event does not have any followers
            if self.graph.out_neighbors_count(v_id) == 0 {
                return None;
            }

            let mut completed: Vec<(VertexId, usize)> = vec![];
            let mut to_traverse: VecDeque<(VertexId, usize)> = self
                .graph
                .out_neighbors(v_id)
                .map(|n| (n.clone(), 1))
                .collect();

            // Find highest followers of all branches
            while let Some((current, following)) = to_traverse.pop_back() {
                if self.graph.out_neighbors_count(&current) == 0 {
                    completed.push((current, following));
                } else {
                    for n in self.graph.out_neighbors(&current) {
                        let neighbor = self.graph.fetch(n).unwrap();
                        let traversed_count = self.graph.out_neighbors_count(n);

                        // In case the next vertex is terminal and belongs to the
                        // given node id, mark current as completed and continue.
                        if traversed_count == 0 && neighbor.node_id() == *node_id {
                            completed.push((current, following));
                            continue;
                        }

                        to_traverse.push_front((n.clone(), following + 1));
                    }
                }
            }

            // Sort by followed events
            completed.sort_by(|a, b| a.1.cmp(&b.1));

            if let Some((result, _)) = completed.pop() {
                Some(self.graph.fetch(&result).unwrap().clone())
            } else {
                None
            }
        } else {
            // The event does not exist in the graph
            return None;
        }
    }

    /// Returns true if the second event happened exactly after the first event.
    pub(crate) fn is_direct_follower(&self, event1: Arc<Event>, event2: Arc<Event>) -> bool {
        let id1 = self.lookup_table.get(&event1.event_hash().unwrap());
        let id2 = self.lookup_table.get(&event2.event_hash().unwrap());

        match (id1, id2) {
            (Some(id1), Some(id2)) => self.graph.has_edge(id2, id1),
            _ => false,
        }
    }

    pub(crate) fn add_validator(&mut self, id: NodeId, can_send: bool, stamp: Stamp) {
        self.validators
            .insert(id, ValidatorState::new(can_send, stamp));
    }

    pub fn empty(&self) -> bool {
        self.graph.vertex_count() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{Hash, Identity};
    use network::NodeId;
    use quickcheck::*;
    use rand::*;

    #[test]
    fn highest_exclusive() {
        let i1 = Identity::new();
        let i2 = Identity::new();
        let n1 = NodeId(*i1.pkey());
        let n2 = NodeId(*i2.pkey());
        let A_hash = Hash::random();
        let A = Arc::new(Event::Dummy(
            n1.clone(),
            A_hash.clone(),
            None,
            Stamp::seed(),
        ));
        let cg = CausalGraph::new_with_test_mode(n1.clone(), A.clone());

        assert_eq!(cg.highest_exclusive(&n2), Some(A));
        assert_eq!(cg.highest_exclusive(&n1), None);
    }

    #[test]
    fn highest_following_with_byzantine_events() {
        let i1 = Identity::new();
        let i2 = Identity::new();
        let n1 = NodeId(*i1.pkey());
        let n2 = NodeId(*i2.pkey());
        let A_hash = Hash::random();
        let B_hash = Hash::random();
        let C1_hash = Hash::random();
        let C2_hash = Hash::random();
        let C3_hash = Hash::random();
        let (s_a, s_b) = Stamp::seed().fork();

        let s_a = s_a.event();
        let A = Arc::new(Event::Dummy(n1.clone(), A_hash.clone(), None, s_a.clone()));
        let s_b = s_b.join(s_a.peek()).event();
        let B = Arc::new(Event::Dummy(
            n2.clone(),
            B_hash.clone(),
            Some(A_hash),
            s_b.clone(),
        ));
        assert!(s_b.happened_after(s_a.clone()));
        let s_a = s_a.join(s_b.peek()).event();
        let C1 = Arc::new(Event::Dummy(
            n1.clone(),
            C1_hash.clone(),
            Some(B_hash),
            s_a.clone(),
        ));
        let C2 = Arc::new(Event::Dummy(
            n1.clone(),
            C2_hash.clone(),
            Some(B_hash),
            s_a.clone(),
        ));
        let C3 = Arc::new(Event::Dummy(
            n1.clone(),
            C3_hash.clone(),
            Some(B_hash),
            s_a.clone(),
        ));
        assert!(s_a.happened_after(s_b.clone()));
        let s_b = s_b.join(s_a.peek()).event();
        let D = Arc::new(Event::Dummy(
            n2.clone(),
            Hash::random(),
            Some(C1_hash),
            s_b.clone(),
        ));
        assert!(s_b.happened_after(s_a));

        let mut cg = CausalGraph::new_with_test_mode(n1.clone(), A.clone());
        let mut events = vec![B.clone(), C1.clone(), C2.clone(), C3.clone(), D.clone()];

        let D = events[4].clone();

        // The causal graph should be the same regardless
        // of the order in which the events are pushed.
        thread_rng().shuffle(&mut events);

        for e in events {
            cg.push(e);
        }

        assert_eq!(cg.highest_following(), Some(D.clone()));
        assert_eq!(cg.compute_highest_following(&n1, A), Some(D));
    }

    quickcheck! {
        fn is_direct_follower() -> bool {
            let i1 = Identity::new();
            let i2 = Identity::new();
            let n1 = NodeId(*i1.pkey());
            let n2 = NodeId(*i2.pkey());
            let A_hash = Hash::random();
            let B_hash = Hash::random();
            let C_hash = Hash::random();
            let (s_a, s_b) = Stamp::seed().fork();

            let s_a = s_a.event();
            let A = Arc::new(Event::Dummy(n1.clone(), A_hash.clone(), None, s_a.clone()));
            let s_b = s_b.join(s_a.peek()).event();
            let B = Arc::new(Event::Dummy(n2.clone(), B_hash.clone(), Some(A_hash), s_b.clone()));
            assert!(s_b.happened_after(s_a.clone()));
            let s_a = s_a.join(s_b.peek()).event();
            let C = Arc::new(Event::Dummy(n1.clone(), C_hash.clone(), Some(B_hash), s_a.clone()));
            assert!(s_a.happened_after(s_b.clone()));
            let s_b = s_b.join(s_a.peek()).event();
            let D = Arc::new(Event::Dummy(n2.clone(), Hash::random(), Some(C_hash), s_b.clone()));
            assert!(s_b.happened_after(s_a));
            let mut cg = CausalGraph::new_with_test_mode(n1.clone(), A.clone());
            let mut events = vec![B.clone(), C.clone(), D.clone()];

            let B = events[0].clone();
            let C = events[1].clone();
            let D = events[2].clone();

            // The causal graph should be the same regardless
            // of the order in which the events are pushed.
            thread_rng().shuffle(&mut events);

            for e in events {
                cg.push(e);
            }

            assert!(cg.is_direct_follower(B.clone(), A.clone()));
            assert!(cg.is_direct_follower(C.clone(), B.clone()));
            assert!(cg.is_direct_follower(D.clone(), C.clone()));
            assert!(!cg.is_direct_follower(A.clone(), B.clone()));
            assert!(!cg.is_direct_follower(A.clone(), C.clone()));
            assert!(!cg.is_direct_follower(D.clone(), A.clone()));
            assert!(!cg.is_direct_follower(C.clone(), A.clone()));
            assert_eq!(cg.highest(), D.clone());
            assert_eq!(cg.highest_exclusive(&n2), Some(C.clone()));
            assert_eq!(cg.highest_following(), Some(D.clone()));
            assert_eq!(cg.compute_highest_following(&n1, A.clone()), Some(D));
            assert_eq!(cg.compute_highest_following(&n2, A), Some(C));

            true
        }

        fn is_direct_follower_mul_paths() -> bool {
            let i = Identity::new();
            let n = NodeId(*i.pkey());
            let A_hash = Hash::random();
            let B_hash = Hash::random();
            let C_hash = Hash::random();
            let D_hash = Hash::random();
            let E_hash = Hash::random();
            let F_hash = Hash::random();
            let A = Arc::new(Event::Dummy(n.clone(), A_hash.clone(), None, Stamp::seed()));
            let B = Arc::new(Event::Dummy(n.clone(), B_hash.clone(), Some(A_hash), Stamp::seed()));
            let C = Arc::new(Event::Dummy(n.clone(), C_hash.clone(), Some(B_hash.clone()), Stamp::seed()));
            let D = Arc::new(Event::Dummy(n.clone(), D_hash.clone(), Some(B_hash), Stamp::seed()));
            let E = Arc::new(Event::Dummy(n.clone(), E_hash.clone(), Some(D_hash.clone()), Stamp::seed()));
            let F = Arc::new(Event::Dummy(n.clone(), F_hash.clone(), Some(D_hash.clone()), Stamp::seed()));
            let G = Arc::new(Event::Dummy(n.clone(), Hash::random(), Some(F_hash), Stamp::seed()));
            let mut cg = CausalGraph::new_with_test_mode(n, A.clone());
            let mut events = vec![B.clone(), C.clone(), D.clone(), E.clone(), F.clone(), G.clone()];

            // The causal graph should be the same regardless
            // of the order in which the events are pushed.
            thread_rng().shuffle(&mut events);

            for e in events {
                cg.push(e);
            }

            assert!(cg.is_direct_follower(B.clone(), A.clone()));
            assert!(cg.is_direct_follower(C.clone(), B.clone()));
            assert!(cg.is_direct_follower(D.clone(), B.clone()));
            assert!(cg.is_direct_follower(E.clone(), D.clone()));
            assert!(cg.is_direct_follower(F.clone(), D.clone()));
            assert!(!cg.is_direct_follower(G.clone(), D.clone()));
            assert!(!cg.is_direct_follower(A.clone(), B.clone()));
            assert!(!cg.is_direct_follower(A.clone(), C.clone()));
            assert!(!cg.is_direct_follower(D, A.clone()));
            assert!(!cg.is_direct_follower(C, A));

            true
        }
    }
}
