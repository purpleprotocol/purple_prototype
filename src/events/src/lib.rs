/*
  Copyright (C) 2018-2019 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

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
extern crate parking_lot;
extern crate patricia_trie;
extern crate persistence;
extern crate rand;
extern crate rayon;
extern crate rlp;
extern crate serde;
extern crate transactions;

#[macro_use]
mod macros;
mod heartbeat;
mod leave;

pub use heartbeat::*;
pub use leave::*;

use causality::Stamp;
use crypto::Hash;
use crypto::NodeId;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use persistence::Codec;
use patricia_trie::TrieDBMut;
use persistence::BlakeDbHasher;

#[derive(Clone, Debug)]
pub enum Event {
    Heartbeat(Heartbeat),
    Leave(Leave),

    /// Dummy event used for testing
    Dummy(NodeId, Hash, Option<Hash>, Stamp),

    /// Represents a placeholder for the root event
    /// in the causal graph when there are no events
    /// stored.
    Root,
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
    pub fn validate_apply(&self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>) -> Result<(), ()> {
        unimplemented!();
    }

    pub fn stamp(&self) -> Stamp {
        match *self {
            Event::Heartbeat(ref event) => event.stamp.clone(),
            Event::Leave(ref event) => event.stamp.clone(),
            Event::Dummy(_, _, _, ref stamp) => stamp.clone(),
            Event::Root => Stamp::seed(),
        }
    }

    pub fn node_id(&self) -> NodeId {
        match *self {
            Event::Heartbeat(ref event) => event.node_id.clone(),
            Event::Leave(ref event) => event.node_id.clone(),
            Event::Dummy(ref node_id, _, _, _) => node_id.clone(),
            Event::Root => unimplemented!(),
        }
    }

    pub fn event_hash(&self) -> Option<Hash> {
        match *self {
            Event::Heartbeat(ref event) => event.hash.clone(),
            Event::Leave(ref event) => event.hash.clone(),
            Event::Dummy(ref node_id, ref hash, _, _) => Some(hash.clone()),
            Event::Root => Some(Hash::NULL),
        }
    }

    pub fn parent_hash(&self) -> Option<Hash> {
        match *self {
            Event::Heartbeat(ref event) => Some(event.parent_hash.clone()),
            Event::Leave(ref event) => Some(event.parent_hash.clone()),
            Event::Dummy(ref node_id, _, ref parent_hash, _) => parent_hash.clone(),
            Event::Root => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Event::Heartbeat(ref event) => event.to_bytes().unwrap(),
            Event::Leave(ref event) => event.to_bytes().unwrap(),
            Event::Dummy(ref node_id, _, ref parent_hash, _) => unimplemented!(),
            Event::Root => unimplemented!(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Event, &'static str> {
        match bytes[0] {
            Heartbeat::EVENT_TYPE => match Heartbeat::from_bytes(bytes) {
                Ok(result) => Ok(Event::Heartbeat(result)),
                Err(err) => Err(err),
            },

            Leave::EVENT_TYPE => match Leave::from_bytes(bytes) {
                Ok(result) => Ok(Event::Leave(result)),
                Err(err) => Err(err),
            },

            _ => Err("Invalid event type"),
        }
    }
}

use quickcheck::Arbitrary;
use rand::prelude::*;

impl Arbitrary for Event {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Event {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);

        match random {
            0 => Event::Heartbeat(Arbitrary::arbitrary(g)),
            1 => Event::Leave(Arbitrary::arbitrary(g)),
            _ => panic!(),
        }
    }
}
