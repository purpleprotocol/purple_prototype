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

use crate::parameters::*;
use events::Event;
use hashbrown::{HashMap, HashSet};
use network::NodeId;
use std::sync::Arc;
use std::hash::Hash;
use std::hash::Hasher;

#[derive(Clone, Debug)]
pub struct Candidate {
    /// Candidate event
    pub event: Arc<Event>,

    /// Mapping between references to events that vote
    /// for the `Candidate`, the number of voters and
    /// the ids of the nodes that voted.
    pub voters: HashMap<Arc<Event>, (u16, HashSet<NodeId>)>,

    /// The ids of the nodes that have sent an
    /// event that votes for this candidate.
    pub voters_ids: HashSet<NodeId>,

    /// Total number of votes.
    pub votes: u16,

    /// Total number of proposals.
    pub proposals: u16,

    /// Whether or not the event is in the proposal stage
    pub proposal_stage: bool,
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Candidate) -> bool {
        self.event.event_hash().unwrap() == other.event.event_hash().unwrap()
    }
}

impl Eq for Candidate {}

impl Hash for Candidate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.event.event_hash().unwrap().hash(state);
    }
}

impl Candidate {
    pub fn new(event: Arc<Event>) -> Candidate {
        Candidate {
            event,
            voters: HashMap::new(),
            voters_ids: HashSet::new(),
            votes: 0,
            proposals: 0,
            proposal_stage: false,
        }
    }

    /// Returns `true` if the candidate event is
    /// valid for inclusion into the total order.
    pub fn is_valid(&self, node_count: u16) -> bool {
        self.proposals >= proposal_requirement(node_count)
    }
}
