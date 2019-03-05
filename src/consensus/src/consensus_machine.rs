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

use parking_lot::Mutex;
use causality::Stamp;
use network::NodeId;
use std::sync::Arc;
use events::Event;
use petgraph::visit::Dfs;
use crate::candidate_set::CandidateSet;
use crate::causal_graph::CausalGraph;
use crate::validator_state::ValidatorState;

#[derive(Clone, Debug)]
pub enum CGError {
    AlreadyInCG,
    NoEventFound,
    NoCandidateSetFound,
    InvalidEvent
}

#[derive(Debug)]
pub struct ConsensusMachine {
    causal_graph: Arc<CausalGraph>,
    candidate_sets: Vec<Arc<Mutex<CandidateSet>>>,
    validators: Vec<Arc<Mutex<ValidatorState>>>,
}

impl ConsensusMachine {
    pub fn new() -> ConsensusMachine {
        ConsensusMachine {
            causal_graph: Arc::new(CausalGraph::new()),
            candidate_sets: Vec::new(),
            validators: Vec::new()
        }
    }

    /// Attempts to push an atomic reference to an
    /// event to the causal graph. This function also
    /// validates the event in accordance with the rest
    /// of the causal graph.
    /// 
    /// This will return `Err(CGError::AlreadyInCG)` if the event
    /// is already situated in the `CausalGraph`.
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
        let graph = &(*self.causal_graph).0;
        
        let mut dfs = Dfs::empty(graph);
        let mut acc = None;
        
        while let Some(i) = dfs.next(graph) {
            if acc.is_none() {
                acc = Some(i);
                continue;
            } 

            let acc_i = acc.unwrap();
            
            // If next happened after accumulated val and it
            // doesn't belong to the given node id, store as 
            // new accumulated value.
            if (*graph[i]).stamp().happened_after((*graph[acc_i]).stamp()) && (*graph[i]).node_id() != *node_id {
                acc = Some(i);
            }
        }

        if let Some(i) = acc {
            Ok(graph[i].clone())
        } else {
            Err(CGError::NoEventFound)
        }
    }

    /// Return the highest event that follows the given 
    /// given stamp in the causal graph that **does not**
    /// belong to the node with the given `NodeId`.
    pub fn highest_following(&self, node_id: &NodeId, stamp: &Stamp) -> Result<Arc<Event>, CGError> {
        unimplemented!();
    }

    /// Returns valid candidate sets that can be included
    /// into the total order.
    pub fn fetch_cs(&self) -> Result<Vec<Arc<Mutex<CandidateSet>>>, CGError> {
        unimplemented!();
    }
}