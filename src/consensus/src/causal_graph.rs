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
use causality::Stamp;
use events::Event;
use network::NodeId;
use std::sync::Arc;
use crate::candidate_set::CandidateSet;

#[derive(Clone, Debug)]
pub enum CGError {
    NoEventFound,
    NoCandidateSetFound,
    InvalidEvent
}

#[derive(Clone, Debug)]
pub struct CausalGraph(StableGraph<Arc<Event>, (), Directed>);

impl CausalGraph {
    pub fn new() -> CausalGraph {
        CausalGraph(StableGraph::new())
    }

    /// Attempts to push an atomic reference to an
    /// event to the causal graph. This function also
    /// validates the event in accordance with the rest
    /// of the causal graph.
    /// 
    /// This will return `Err(CGError::InvalidEvent)` if the 
    /// event that the given reference points to is invalid.
    pub fn push(&mut self, event: Arc<Event>) -> Result<(), CGError> {
        unimplemented!();
    }

    /// Returns the highest event in the causal graph
    /// that **does not** belong to the node with the
    /// given `NodeId`. 
    pub fn highest(&self, node_id: &NodeId) -> Result<Arc<Event>, CGError> {
        unimplemented!();
    }

    /// Return the highest event that follows the given 
    /// given stamp in the causal graph that **does not**
    /// belong to the node with the given `NodeId`.
    pub fn highest_following(&self, node_id: &NodeId, stamp: &Stamp) -> Result<Arc<Event>, CGError> {
        unimplemented!();
    }

    /// Returns valid candidate sets that can be included
    /// into the total order.
    pub fn fetch_cs(&self) -> Result<CandidateSet, CGError> {
        unimplemented!();
    }
}