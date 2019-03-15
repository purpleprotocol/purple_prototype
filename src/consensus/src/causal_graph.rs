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
use graphlib::Graph;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct CausalGraph(pub Graph<Arc<Event>>);

impl CausalGraph {
    pub fn new() -> CausalGraph {
        CausalGraph(Graph::new())
    }

    /// Returns `true` if any event from the `CausalGraph`
    /// matches the given condition closure.
    pub fn any<F>(&self, fun: F) -> bool
    where
        F: Fn(Arc<Event>) -> bool,
    {
        for v in self.0.vertices() {
            if fun(self.0.fetch(v).unwrap().clone()) {
                return true;
            }
        }

        false
    }

    pub fn empty(&self) -> bool {
        self.0.vertex_count() == 0
    }
}
