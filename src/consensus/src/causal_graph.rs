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
    pub graph: Graph<Arc<Event>>,
    lookup_table: HashMap<Hash, VertexId>, 
}

impl CausalGraph {
    pub fn new() -> CausalGraph {
        CausalGraph {
            graph: Graph::new(),
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

    pub fn add_vertex(&mut self, event: Arc<Event>) {
        let id = self.graph.add_vertex(event.clone());
        self.lookup_table.insert(event.hash().unwrap(), id);
    }

    /// Returns true if the second event happened exactly after the first event.
    pub fn is_direct_follower(&self, event1: Arc<Event>, event2: Arc<Event>) -> bool {
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
