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

    /// Events that do not yet directly follow
    /// other events from the causal graph.
    pending: HashSet<VertexId>,

    /// A mapping between events that follow other events
    /// but do not have any follower and the number of
    /// followed events.
    ends: HashMap<VertexId, usize>,

    /// Mapping between event hashes and vertex ids.
    lookup_table: HashMap<Hash, VertexId>,

    /// The current highest event in the graph and
    /// the number of followed events.
    highest: (Arc<Event>, usize),
}

impl CausalGraph {
    pub fn new(root_event: Arc<Event>) -> CausalGraph {
        let mut graph = Graph::new();
        let mut lookup_table = HashMap::new();
        let mut ends = HashMap::new();
        let id = graph.add_vertex(root_event.clone());

        lookup_table.insert(root_event.hash().unwrap(), id.clone());
        ends.insert(id, 0);

        CausalGraph {
            graph,
            ends,
            lookup_table,
            pending: HashSet::new(),
            highest: (root_event, 0),
        }
    }

    /// Returns `true` if any event from the `CausalGraph`
    /// matches the given condition closure.
    pub fn any<F>(&self, fun: F) -> bool
    where
        F: Fn(Arc<Event>) -> bool,
    {
        for v in self.graph.dfs() {
            if fun(self.graph.fetch(v).unwrap().clone()) {
                return true;
            }
        }

        false
    }

    pub fn contains(&self, event: Arc<Event>) -> bool {
        self.lookup_table.get(&event.hash().unwrap()).is_some()
    }

    pub fn push(&mut self, event: Arc<Event>) {
        if event.parent_hash().is_none() {
            panic!("Pushing an event without a parent hash is illegal!");
        }

        if !self.contains(event.clone()) {
            let id = self.graph.add_vertex(event.clone());
            self.lookup_table.insert(event.hash().unwrap(), id.clone());
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
                    return;
                }

                if let Some((current_end_id, current_following)) = ends.pop_back() {
                    let current_end = self.graph.fetch(&current_end_id).unwrap();
                    let mut to_remove = Vec::with_capacity(self.pending.len());
                    let mut to_add = Vec::with_capacity(self.pending.len());
                    let mut found_match = false;

                    for e in self.pending.iter() {
                        let current = self.graph.fetch(e).unwrap();

                        // Add edge if matching child is found
                        if current.parent_hash() == current_end.hash() {
                            let new_following = current_following + 1;

                            to_remove.push(e.clone());
                            self.ends.insert(e.clone(), new_following);
                            self.ends.remove(&current_end_id);
                            to_add.push((current_end_id, e.clone()));
                            ends.push_front((*e, new_following));

                            // Cache new highest event if this is the case
                            if new_following > self.highest.1 {
                                self.highest = (current.clone(), new_following);
                            }

                            found_match = true;
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

                    for e in to_remove.iter() {
                        self.pending.remove(e);
                    }

                    for e in to_add.iter() {
                        self.graph.add_edge(&e.0, &e.1).unwrap();
                    }
                } else {
                    return;
                }
            }
        } else {
            panic!("Cannot push an already contained event!");
        }
    }

    pub(crate) fn highest(&self, node_id: &NodeId) -> Arc<Event> {
        self.highest.0.clone()
    }

    pub(crate) fn highest_following(&self, node_id: &NodeId, stamp: &Stamp) -> Option<Arc<Event>> {
        unimplemented!();
    }

    /// Returns true if the second event happened exactly after the first event.
    pub(crate) fn is_direct_follower(&self, event1: Arc<Event>, event2: Arc<Event>) -> bool {
        let id1 = self.lookup_table.get(&event1.hash().unwrap());
        let id2 = self.lookup_table.get(&event2.hash().unwrap());

        match (id1, id2) {
            (Some(id1), Some(id2)) => self.graph.has_edge(id2, id1),
            _ => false,
        }
    }

    pub fn empty(&self) -> bool {
        self.graph.vertex_count() == 0
    }
}

#[cfg(test)]
mod tests {
    #[macro_use]
    use quickcheck::*;
    use super::*;
    use causality::Stamp;
    use crypto::{Hash, Identity};
    use network::NodeId;
    use rand::*;

    quickcheck! {
        fn is_direct_follower() -> bool {
            let i1 = Identity::new();
            let i2 = Identity::new();
            let n1 = NodeId(*i1.pkey());
            let n2 = NodeId(*i2.pkey());
            let A_hash = Hash::random();
            let B_hash = Hash::random();
            let C_hash = Hash::random();
            let A = Arc::new(Event::Dummy(n1.clone(), A_hash.clone(), None, Stamp::seed()));
            let B = Arc::new(Event::Dummy(n2.clone(), B_hash.clone(), Some(A_hash), Stamp::seed()));
            let C = Arc::new(Event::Dummy(n1.clone(), C_hash.clone(), Some(B_hash), Stamp::seed()));
            let D = Arc::new(Event::Dummy(n2.clone(), Hash::random(), Some(C_hash), Stamp::seed()));
            let mut cg = CausalGraph::new(A.clone());

            let mut events = vec![B.clone(), C.clone(), D.clone()];

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
            assert!(!cg.is_direct_follower(C, A));
            assert_eq!(cg.highest(&n1), D);

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
            let mut cg = CausalGraph::new(A.clone());

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
