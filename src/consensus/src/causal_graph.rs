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

use events::Event;
use crypto::Hash;
use graphlib::{Graph, VertexId};
use std::sync::Arc;
use std::collections::VecDeque;
use hashbrown::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct CausalGraph {
    /// Graph structure holding the causal graph
    pub graph: Graph<Arc<Event>>,

    /// Events that do not yet directly follow
    /// other events from the causal graph. 
    pending: HashSet<VertexId>,

    /// A set of events that follow other events
    /// but do not have any follower.
    ends: HashSet<VertexId>,

    /// Mapping between event hashes and vertex ids.
    lookup_table: HashMap<Hash, VertexId>, 
}

impl CausalGraph {
    pub fn new(root_event: Arc<Event>) -> CausalGraph {
        let mut graph = Graph::new();
        let mut lookup_table = HashMap::new();
        let mut ends = HashSet::new();
        let id = graph.add_vertex(root_event.clone());
        
        lookup_table.insert(root_event.hash().unwrap(), id.clone());
        ends.insert(id);

        CausalGraph {
            graph,
            ends,
            lookup_table,
            pending: HashSet::new(),
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

            let mut ends: VecDeque<VertexId> = self.ends.iter().cloned().collect();

            // Loop graph ends and for each one, try to 
            // attach a pending event until either the 
            // pending set is empty or until we have
            // traversed each end vertex.
            loop {
                if self.pending.is_empty() {
                    return;
                }

                if let Some(current_end_id) = ends.pop_back() {
                    let current_end = self.graph.fetch(&current_end_id).unwrap();
                    let mut to_remove = Vec::with_capacity(self.pending.len());
                    let mut to_add = Vec::with_capacity(self.pending.len());

                    for e in self.pending.iter() {
                        let current = self.graph.fetch(e).unwrap();

                        // Add edge if matching child is found
                        if current.parent_hash() == current_end.hash() {
                            to_remove.push(e.clone());
                            self.ends.insert(e.clone());
                            self.ends.remove(&current_end_id);
                            to_add.push((current_end_id, e.clone()));
                            ends.push_front(*e);
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

    /// Returns true if the second event happened exactly after the first event.
    pub(crate) fn is_direct_follower(&self, event1: Arc<Event>, event2: Arc<Event>) -> bool {
        let id1 = self.lookup_table.get(&event1.hash().unwrap());
        let id2 = self.lookup_table.get(&event2.hash().unwrap());

        match (id1, id2) {
            (Some(id1), Some(id2)) => {
                self.graph.has_edge(id2, id1)
            },
            _ => false
        }
    }

    pub fn empty(&self) -> bool {
        self.graph.vertex_count() == 0
    }
}

#[cfg(test)]
mod tests {
    #[macro_use] use quickcheck::*;
    use super::*;
    use crypto::{Identity, Hash};
    use causality::Stamp;
    use rand::*;
    use network::NodeId;

    quickcheck! {
        fn is_direct_follower() -> bool {
            let i = Identity::new();
            let n = NodeId(*i.pkey());
            let A_hash = Hash::random();
            let B_hash = Hash::random();
            let C_hash = Hash::random();
            let A = Arc::new(Event::Dummy(n.clone(), A_hash.clone(), None, Stamp::seed()));
            let B = Arc::new(Event::Dummy(n.clone(), B_hash.clone(), Some(A_hash), Stamp::seed()));
            let C = Arc::new(Event::Dummy(n.clone(), C_hash.clone(), Some(B_hash), Stamp::seed()));
            let D = Arc::new(Event::Dummy(n.clone(), Hash::random(), Some(C_hash), Stamp::seed()));
            let mut cg = CausalGraph::new(A.clone());

            let mut events = vec![B.clone(), C.clone(), D.clone()];

            // The causal graph should be the same regardless
            // of the order in which the events are pushed.
            thread_rng().shuffle(&mut events);

            for e in events {
                println!("DEBUG PUSHED: {:?}", e);
                cg.push(e);
            }

            assert!(cg.is_direct_follower(B.clone(), A.clone()));
            assert!(cg.is_direct_follower(C.clone(), B.clone()));
            assert!(cg.is_direct_follower(D.clone(), C.clone()));
            assert!(!cg.is_direct_follower(A.clone(), B.clone()));
            assert!(!cg.is_direct_follower(A.clone(), C.clone()));
            assert!(!cg.is_direct_follower(D, A.clone()));
            assert!(!cg.is_direct_follower(C, A));

            println!("SUCCESS!");

            true
        }
    }
}