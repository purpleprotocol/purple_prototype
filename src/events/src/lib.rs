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

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[macro_use]
extern crate serde_derive;

extern crate account;
extern crate bitvec;
extern crate byteorder;
extern crate causality;
extern crate crypto;
extern crate merkle_light;
extern crate network;
extern crate parking_lot;
extern crate patricia_trie;
extern crate persistence;
extern crate rayon;
extern crate rlp;
extern crate serde;
extern crate transactions;

#[macro_use]
mod macros;
mod heartbeat;
mod join;
mod leave;

pub use heartbeat::*;
pub use join::*;
pub use leave::*;

use causality::Stamp;
use crypto::Hash;
use network::NodeId;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;

#[derive(Clone, Debug)]
pub enum Event {
    Heartbeat(Heartbeat),
    Join(Join),
    Leave(Leave),

    /// Dummy event used for testing
    Dummy(NodeId, Hash, Option<Hash>, Stamp),
}

impl PartialEq for Event {
    fn eq(&self, other: &Event) -> bool {
        // This only makes sense when the event is received
        // when the node is a server i.e. when the event is
        // guaranteed to have a hash because it already passed
        // the parsing stage.
        self.event_hash().unwrap() == other.event_hash().unwrap()
    }
}

impl Eq for Event {}

impl HashTrait for Event {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.event_hash().unwrap().hash(state);
    }
}

impl Event {
    pub fn stamp(&self) -> Stamp {
        match *self {
            Event::Heartbeat(ref event) => event.stamp.clone(),
            Event::Join(ref event) => event.stamp.clone(),
            Event::Leave(ref event) => event.stamp.clone(),
            Event::Dummy(_, _, _, ref stamp) => stamp.clone(),
        }
    }

    pub fn node_id(&self) -> NodeId {
        match *self {
            Event::Heartbeat(ref event) => event.node_id.clone(),
            Event::Join(ref event) => event.node_id.clone(),
            Event::Leave(ref event) => event.node_id.clone(),
            Event::Dummy(ref node_id, _, _, _) => node_id.clone(),
        }
    }

    pub fn event_hash(&self) -> Option<Hash> {
        match *self {
            Event::Heartbeat(ref event) => event.hash.clone(),
            Event::Join(ref event) => event.hash.clone(),
            Event::Leave(ref event) => event.hash.clone(),
            Event::Dummy(ref node_id, ref hash, _, _) => Some(hash.clone()),
        }
    }

    pub fn parent_hash(&self) -> Option<Hash> {
        match *self {
            Event::Heartbeat(ref event) => Some(event.parent_hash.clone()),
            Event::Join(ref event) => event.parent_cg_hash.clone(),
            Event::Leave(ref event) => Some(event.parent_hash.clone()),
            Event::Dummy(ref node_id, _, ref parent_hash, _) => parent_hash.clone(),
        }
    }
}
