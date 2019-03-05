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

use petgraph::stable_graph::StableGraph;
use petgraph::Directed;
use events::Event;
use petgraph::visit::Dfs;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct CausalGraph(pub StableGraph<Arc<Event>, (), Directed>);

impl CausalGraph {
    pub fn new() -> CausalGraph {
        CausalGraph(StableGraph::new())
    }

    /// Returns `true` if any event from the `CausalGraph`
    /// matches the given condition closure.
    pub fn any(&self, fun: &Fn(Arc<Event>) -> bool) -> bool {
        let mut dfs = Dfs::empty(&self.0);

        while let Some(i) = dfs.next(&self.0) {
            if fun(self.0[i].clone()) {
                return true;
            }
        }

        false
    }
}