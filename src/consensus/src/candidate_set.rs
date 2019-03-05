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

use std::sync::Arc;
use events::Event;
use crate::causal_graph::CausalGraph;
use crate::parameters::*;

#[derive(Clone, Debug)]
pub struct CandidateSet {
    /// Atomic references to events that are
    /// situated in the `CandidateSet`.
    pub events: Vec<Arc<Event>>,

    /// Atomic references to events that vote
    /// for the `CandidateSet`.
    pub voters: Vec<Arc<Event>>,

    /// Total number of votes.
    pub votes: u16,

    /// Total number of proposals.
    pub proposals: u16
}

impl CandidateSet {
    pub fn new(events: &[Arc<Event>]) -> CandidateSet {
        CandidateSet {
            events: events.to_vec(),
            voters: Vec::new(),
            votes: 0,
            proposals: 0
        }
    }

    /// Returns `true` if the events in the `CandidateSet`
    /// are valid for inclusion into the total order.
    pub fn is_valid(&self, node_count: u16) -> bool { self.proposals >= proposal_requirement(node_count) }

    /// Counts the number of votes and proposals
    /// of the `CandidateSet` based on the provided
    /// `CausalGraph`.
    /// 
    /// This function will panic if any event in 
    /// the `CandidateSet` is not residing in the
    /// provided `CausalGraph`. 
    pub fn count_votes(&mut self, causal_graph: Arc<CausalGraph>) {
        unimplemented!();
    }
}