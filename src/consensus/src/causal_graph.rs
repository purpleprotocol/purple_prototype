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
use hashbrown::HashMap;

#[derive(Clone, Debug)]
pub struct CausalGraph {
    /// Graph structure holding the causal graph
    pub graph: Graph<Arc<Event>>,

    /// Events that do not yet directly follow
    /// other events from the causal graph and
    /// the number of events that have been 
    /// added and follow another event since
    /// the pending event has been pushed. 
    pending: HashMap<Arc<Event>, usize>,

    /// Mapping between event hashes and vertex ids.
    lookup_table: HashMap<Hash, VertexId>, 
}

impl CausalGraph {
    pub fn new() -> CausalGraph {
        CausalGraph {
            graph: Graph::new(),
            pending: HashMap::new(),
            lookup_table: HashMap::new()
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

    pub fn add_vertex(&mut self, event: Arc<Event>) -> VertexId {
        let id = self.graph.add_vertex(event.clone());
        self.lookup_table.insert(event.hash().unwrap(), id.clone());

        id
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
    use super::*;
    use crypto::{Identity, Hash};
    use causality::Stamp;
    use network::NodeId;

    #[test]
    fn is_direct_follower() {
        let i = Identity::new();
        let n = NodeId(*i.pkey());
        let A = Arc::new(Event::Dummy(n.clone(), Some(Hash::random()), Stamp::seed()));
        let B = Arc::new(Event::Dummy(n.clone(), Some(Hash::random()), Stamp::seed()));
        let C = Arc::new(Event::Dummy(n.clone(), Some(Hash::random()), Stamp::seed()));
        let D = Arc::new(Event::Dummy(n.clone(), Some(Hash::random()), Stamp::seed()));
        let mut cg = CausalGraph::new();

        let A_id = cg.add_vertex(A.clone());
        let B_id = cg.add_vertex(B.clone());
        let C_id = cg.add_vertex(C.clone());
        let D_id = cg.add_vertex(D.clone());

        cg.graph.add_edge(&A_id, &B_id).unwrap();
        cg.graph.add_edge(&B_id, &C_id).unwrap();

        assert!(cg.is_direct_follower(B.clone(), A.clone()));
        assert!(cg.is_direct_follower(C.clone(), B.clone()));
        assert!(!cg.is_direct_follower(A.clone(), B.clone()));
        assert!(!cg.is_direct_follower(A.clone(), C.clone()));
        assert!(!cg.is_direct_follower(D, A.clone()));
        assert!(!cg.is_direct_follower(C, A));
    }
}