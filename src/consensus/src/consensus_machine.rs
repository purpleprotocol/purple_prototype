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

use crate::causal_graph::CausalGraph;
use events::Event;
use network::NodeId;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum CGError {
    AlreadyInCG,
    NoEventFound,
    NoCandidateSetFound,
    InvalidEvent,
}

#[derive(Debug)]
pub struct ConsensusMachine {
    pub(crate) causal_graph: CausalGraph,
}

impl ConsensusMachine {
    pub fn new(node_id: NodeId, root_event: Arc<Event>) -> ConsensusMachine {
        ConsensusMachine {
            causal_graph: CausalGraph::new(node_id, root_event),
        }
    }

    pub fn is_valid(&self, event: Arc<Event>) -> bool {
        unimplemented!();
    }

    /// Attempts to push an atomic reference to an
    /// event to the causal graph. This function will
    /// return any events that have been totally ordered
    /// if successful.
    ///
    /// This will return `Err(CGError::AlreadyInCG)` if the event
    /// is already situated in the `CausalGraph`.
    pub fn push(&mut self, event: Arc<Event>) -> Result<Vec<Arc<Event>>, CGError> {
        if self.causal_graph.contains(event.clone()) {
            return Err(CGError::AlreadyInCG);
        }

        Ok(self.causal_graph.push(event))
    }

    /// Returns the highest event that is currently
    /// residing in the causal graph.
    pub fn highest(&self) -> Arc<Event> {
        self.causal_graph.highest()
    }

    /// Returns the highest event in the causal graph
    /// that **does not** belong to the node with the
    /// given `NodeId`.
    pub fn highest_exclusive(&self, node_id: &NodeId) -> Option<Arc<Event>> {
        self.causal_graph.highest_exclusive(node_id)
    }

    /// Return the highest event that follows the our latest
    /// sent event in the causal graph that **does not**
    /// belong to ourselves.
    pub fn highest_following(&self) -> Option<Arc<Event>> {
        self.causal_graph.highest_following()
    }

    /// Return the highest event that follows the given
    /// given event in the causal graph that **does not**
    /// belong to the node with the given `NodeId`.
    pub fn compute_highest_following(
        &self,
        node_id: &NodeId,
        event: Arc<Event>,
    ) -> Option<Arc<Event>> {
        self.causal_graph.compute_highest_following(node_id, event)
    }

    /// Returns true if the second event happened exactly after the first event.
    pub(crate) fn is_direct_follower(&self, event1: Arc<Event>, event2: Arc<Event>) -> bool {
        self.causal_graph.is_direct_follower(event1, event2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use causality::Stamp;
    use crypto::{Hash, Identity};
    use quickcheck::*;
    use rand::{thread_rng, Rng};

    #[test]
    /// Causal graph structure:
    ///
    /// A -> B -> C -> D -> E -> F
    /// |
    /// A' -> B' -> C' -> D'
    ///       |
    ///       B''
    ///
    /// The intended result for calling the function on A should be F
    /// and the intended result for A' should be D'.
    fn highest_following() {
        let i1 = Identity::new();
        let i2 = Identity::new();
        let i3 = Identity::new();
        let n1 = NodeId(*i1.pkey());
        let n2 = NodeId(*i2.pkey());
        let n3 = NodeId(*i3.pkey());
        let seed = Stamp::seed();
        let (s_a, s_b) = seed.fork();
        let (s_b, s_c) = s_b.fork();
        let (s_a, s_d) = s_a.fork();

        let s_a = s_a.event();
        let A_hash = Hash::random();
        let A = Event::Dummy(n1.clone(), A_hash.clone(), None, s_a.clone());

        let s_c = s_c.join(s_a.peek()).event();
        let A_prime_hash = Hash::random();
        let A_prime = Event::Dummy(
            n3.clone(),
            A_prime_hash.clone(),
            Some(A_hash.clone()),
            s_c.clone(),
        );

        let s_c = s_c.event();
        let B_prime_hash = Hash::random();
        let B_prime = Event::Dummy(
            n3.clone(),
            B_prime_hash.clone(),
            Some(A_prime_hash),
            s_c.clone(),
        );

        let s_d = s_d.join(s_c.peek()).event();
        let B_second = Event::Dummy(
            n3.clone(),
            Hash::random(),
            Some(B_prime_hash.clone()),
            s_d.clone(),
        );

        let s_c = s_c.event();
        let C_prime_hash = Hash::random();
        let C_prime = Event::Dummy(
            n3.clone(),
            C_prime_hash.clone(),
            Some(B_prime_hash),
            s_c.clone(),
        );

        let s_c = s_c.event();
        let D_prime = Event::Dummy(n3, Hash::random(), Some(C_prime_hash.clone()), s_c);

        let s_b = s_b.join(s_a.peek()).event();
        let B_hash = Hash::random();
        let B = Event::Dummy(n2.clone(), B_hash.clone(), Some(A_hash), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let C_hash = Hash::random();
        let C = Event::Dummy(n1.clone(), C_hash.clone(), Some(B_hash), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let D_hash = Hash::random();
        let D = Event::Dummy(n2.clone(), D_hash.clone(), Some(C_hash), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let E_hash = Hash::random();
        let E = Event::Dummy(n1.clone(), E_hash.clone(), Some(D_hash), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F_hash = Hash::random();
        let F = Event::Dummy(n2.clone(), F_hash, Some(E_hash), s_b.clone());

        let events = vec![
            A, B, C, D, E, F, A_prime, B_prime, C_prime, D_prime, B_second,
        ];

        let events: Vec<Arc<Event>> = events.iter().map(|e| Arc::new(e.clone())).collect();

        let A = events[0].clone();
        let F = events[5].clone();
        let A_prime = events[6].clone();
        let D_prime = events[9].clone();

        let (_, events) = events.split_at(1);
        let mut events: Vec<Arc<Event>> = events.iter().cloned().collect();

        // The causal graph should be the same regardless
        // of the order in which the events are pushed.
        thread_rng().shuffle(&mut events);

        let mut machine = ConsensusMachine::new(n1.clone(), A.clone());

        // Populate validator set so the tests pass when param checks are made
        for _ in 0..100 {
            let i = Identity::new();
            let n = NodeId(*i.pkey());
            machine.causal_graph.add_validator(n);
        }

        for e in events {
            machine.push(e).unwrap();
        }

        assert_eq!(machine.highest_following().unwrap(), F.clone());
        assert_eq!(
            machine.compute_highest_following(&n1, A.clone()).unwrap(),
            F
        );
        assert_eq!(
            machine
                .compute_highest_following(&n2, A_prime.clone())
                .unwrap(),
            D_prime
        );
    }

    #[test]
    /// Causal graph structure:
    ///
    /// A -> B -> C -> D -> E -> F
    /// |
    /// A' -> B' -> C' -> D'
    ///       |
    ///       A''
    ///
    /// The intended result for calling the function should be F.
    fn highest() {
        let i1 = Identity::new();
        let i2 = Identity::new();
        let i3 = Identity::new();
        let n1 = NodeId(*i1.pkey());
        let n2 = NodeId(*i2.pkey());
        let n3 = NodeId(*i3.pkey());
        let seed = Stamp::seed();
        let (s_a, s_b) = seed.fork();
        let (s_b, s_c) = s_b.fork();
        let (s_a, s_d) = s_a.fork();

        let s_a = s_a.event();
        let A_hash = Hash::random();
        let A = Event::Dummy(n1.clone(), A_hash.clone(), None, s_a.clone());

        let s_c = s_c.join(s_a.peek()).event();
        let A_prime_hash = Hash::random();
        let A_prime = Event::Dummy(
            n3.clone(),
            A_prime_hash.clone(),
            Some(A_hash.clone()),
            s_c.clone(),
        );

        let s_c = s_c.event();
        let B_prime_hash = Hash::random();
        let B_prime = Event::Dummy(
            n3.clone(),
            B_prime_hash.clone(),
            Some(A_prime_hash),
            s_c.clone(),
        );

        let s_d = s_d.join(s_c.peek()).event();
        let B_second = Event::Dummy(
            n3.clone(),
            Hash::random(),
            Some(B_prime_hash.clone()),
            s_d.clone(),
        );

        let s_c = s_c.event();
        let C_prime_hash = Hash::random();
        let C_prime = Event::Dummy(
            n3.clone(),
            C_prime_hash.clone(),
            Some(B_prime_hash),
            s_c.clone(),
        );

        let s_c = s_c.event();
        let D_prime = Event::Dummy(n3, Hash::random(), Some(C_prime_hash.clone()), s_c);

        let s_b = s_b.join(s_a.peek()).event();
        let B_hash = Hash::random();
        let B = Event::Dummy(n2.clone(), B_hash.clone(), Some(A_hash), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let C_hash = Hash::random();
        let C = Event::Dummy(n1.clone(), C_hash.clone(), Some(B_hash), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let D_hash = Hash::random();
        let D = Event::Dummy(n2.clone(), D_hash.clone(), Some(C_hash), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let E_hash = Hash::random();
        let E = Event::Dummy(n1.clone(), E_hash.clone(), Some(D_hash), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F_hash = Hash::random();
        let F = Event::Dummy(n2.clone(), F_hash, Some(E_hash), s_b.clone());

        let events = vec![
            A, B, C, D, E, F, A_prime, B_prime, C_prime, D_prime, B_second,
        ];

        let events: Vec<Arc<Event>> = events.iter().map(|e| Arc::new(e.clone())).collect();

        let A = events[0].clone();
        let E = events[4].clone();
        let F = events[5].clone();

        let (_, events) = events.split_at(1);
        let mut events: Vec<Arc<Event>> = events.iter().cloned().collect();

        // The causal graph should be the same regardless
        // of the order in which the events are pushed.
        thread_rng().shuffle(&mut events);

        let mut machine = ConsensusMachine::new(n1, A.clone());

        // Populate validator set so the tests pass when param checks are made
        for _ in 0..100 {
            let i = Identity::new();
            let n = NodeId(*i.pkey());
            machine.causal_graph.add_validator(n);
        }

        for e in events {
            machine.push(e).unwrap();
        }

        assert_eq!(machine.highest(), F);
        assert_eq!(machine.highest_exclusive(&n2), Some(E));
    }

    quickcheck! {
        /// Causal graph structure:
        ///
        /// A -> B -> C -> D -> E -> F
        /// |
        /// A' -> B' -> C' -> D'
        ///       |
        ///       B''
        fn graph_assembly() -> bool {
            let i1 = Identity::new();
            let i2 = Identity::new();
            let i3 = Identity::new();
            let n1 = NodeId(*i1.pkey());
            let n2 = NodeId(*i2.pkey());
            let n3 = NodeId(*i3.pkey());
            let seed = Stamp::seed();
            let (s_a, s_b) = seed.fork();
            let (s_b, s_c) = s_b.fork();
            let (s_a, s_d) = s_a.fork();

            let s_a = s_a.event();
            let A_hash = Hash::random();
            let A = Event::Dummy(n1.clone(), A_hash.clone(), None, s_a.clone());

            let s_c = s_c.join(s_a.peek()).event();
            let A_prime_hash = Hash::random();
            let A_prime = Event::Dummy(n3.clone(), A_prime_hash.clone(), Some(A_hash.clone()), s_c.clone());

            let s_c = s_c.event();
            let B_prime_hash = Hash::random();
            let B_prime = Event::Dummy(n3.clone(), B_prime_hash.clone(), Some(A_prime_hash), s_c.clone());

            let s_d = s_d.join(s_c.peek()).event();
            let B_second = Event::Dummy(n3.clone(), Hash::random(), Some(B_prime_hash.clone()), s_d.clone());

            let s_c = s_c.event();
            let C_prime_hash = Hash::random();
            let C_prime = Event::Dummy(n3.clone(), C_prime_hash.clone(), Some(B_prime_hash), s_c.clone());

            let s_c = s_c.event();
            let D_prime = Event::Dummy(n3, Hash::random(), Some(C_prime_hash.clone()), s_c);

            let s_b = s_b.join(s_a.peek()).event();
            let B_hash = Hash::random();
            let B = Event::Dummy(n2.clone(), B_hash.clone(), Some(A_hash), s_b.clone());

            let s_a = s_a.join(s_b.peek()).event();
            let C_hash = Hash::random();
            let C = Event::Dummy(n1.clone(), C_hash.clone(), Some(B_hash), s_a.clone());

            let s_b = s_b.join(s_a.peek()).event();
            let D_hash = Hash::random();
            let D = Event::Dummy(n2.clone(), D_hash.clone(), Some(C_hash), s_b.clone());

            let s_a = s_a.join(s_b.peek()).event();
            let E_hash = Hash::random();
            let E = Event::Dummy(n1.clone(), E_hash.clone(), Some(D_hash), s_a.clone());

            let s_b = s_b.join(s_a.peek()).event();
            let F_hash = Hash::random();
            let F = Event::Dummy(n2.clone(), F_hash, Some(E_hash), s_b.clone());

            assert!(A.stamp().happened_before(B.stamp()));
            assert!(!B.stamp().happened_before(A.stamp()));
            assert!(B.stamp().happened_before(C.stamp()));
            assert!(C.stamp().happened_before(D.stamp()));
            assert!(D.stamp().happened_before(F.stamp()));
            assert!(A.stamp().happened_before(B_prime.stamp()));
            assert!(A.stamp().happened_before(A_prime.stamp()));
            assert!(A_prime.stamp().happened_before(B_prime.stamp()));
            assert!(A_prime.stamp().concurrent(F.stamp()));
            assert!(B_second.stamp().concurrent(D_prime.stamp()));

            let events = vec![
                A,
                B,
                C,
                D,
                E,
                F,
                A_prime,
                B_prime,
                C_prime,
                D_prime,
                B_second
            ];

            let events: Vec<Arc<Event>> = events
                .iter()
                .map(|e| Arc::new(e.clone()))
                .collect();

            let A = events[0].clone();
            let B = events[1].clone();
            let C = events[2].clone();
            let D = events[3].clone();
            let E = events[4].clone();
            let F = events[5].clone();
            let A_prime = events[6].clone();
            let B_prime = events[7].clone();
            let C_prime = events[8].clone();
            let D_prime = events[9].clone();
            let B_second = events[10].clone();

            let (_, events) = events.split_at(1);
            let mut events: Vec<Arc<Event>> = events.iter().cloned().collect();

            // The causal graph should be the same regardless
            // of the order in which the events are pushed.
            thread_rng().shuffle(&mut events);

            let mut machine = ConsensusMachine::new(n1, A.clone());

            // Populate validator set so the tests pass when param checks are made
            for _ in 0..100 {
                let i = Identity::new();
                let n = NodeId(*i.pkey());
                machine.causal_graph.add_validator(n);
            }

            for e in events {
                machine.push(e).unwrap();
            }

            assert!(!machine.causal_graph.graph.is_cyclic());
            assert!(machine.is_direct_follower(B.clone(), A.clone()));
            assert!(machine.is_direct_follower(C.clone(), B.clone()));
            assert!(machine.is_direct_follower(D.clone(), C.clone()));
            assert!(machine.is_direct_follower(E.clone(), D.clone()));
            assert!(machine.is_direct_follower(F.clone(), E));
            assert!(machine.is_direct_follower(A_prime.clone(), A.clone()));
            assert!(machine.is_direct_follower(B_prime.clone(), A_prime));
            assert!(machine.is_direct_follower(C_prime.clone(), B_prime.clone()));
            assert!(machine.is_direct_follower(D_prime.clone(), C_prime));
            assert!(machine.is_direct_follower(B_second, B_prime.clone()));
            assert!(!machine.is_direct_follower(A.clone(), B.clone()));
            assert!(!machine.is_direct_follower(F.clone(), A.clone()));
            assert!(!machine.is_direct_follower(A, F.clone()));
            assert!(!machine.is_direct_follower(B_prime.clone(), B));
            assert!(!machine.is_direct_follower(B_prime.clone(), C));
            assert!(!machine.is_direct_follower(B_prime.clone(), D));
            assert!(!machine.is_direct_follower(B_prime, F));

            true
        }
    }
}
