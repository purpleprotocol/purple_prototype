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

use crate::candidate_set::CandidateSet;
use crate::causal_graph::CausalGraph;
use crate::validator_state::ValidatorState;
use causality::Stamp;
use events::Event;
use network::NodeId;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use graphlib::{VertexId, Graph};
use std::sync::Arc;
use recursive::*;

#[derive(Clone, Debug)]
pub enum CGError {
    AlreadyInCG,
    NoEventFound,
    NoCandidateSetFound,
    InvalidEvent,
}

#[derive(Debug)]
pub struct ConsensusMachine {
    causal_graph: Arc<RwLock<CausalGraph>>,
    candidate_sets: Vec<Arc<Mutex<CandidateSet>>>,
    validators: Vec<Arc<Mutex<ValidatorState>>>,
}

enum Direction {
    Incoming,
    Outgoing
}

impl ConsensusMachine {
    pub fn new() -> ConsensusMachine {
        ConsensusMachine {
            causal_graph: Arc::new(RwLock::new(CausalGraph::new())),
            candidate_sets: Vec::new(),
            validators: Vec::new(),
        }
    }

    /// Returns true if the second event happened exactly after the first event.
    pub fn is_direct_follower(&self, event1: Arc<Event>, event2: Arc<Event>) -> bool {
        self.causal_graph.read().is_direct_follower(event1, event2)
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
        let mut g = self.causal_graph.write();
        let event_stamp = event.stamp();

        // if graph.any(|e| e == event) {
        //     return Err(CGError::AlreadyInCG);
        // }

        // If the causal graph is empty,
        // just append a new node and return.
        if g.graph.vertex_count() == 0 {
            g.graph.add_vertex(event);
            return Ok(());
        }

        // Append node to graph
        let pushed = g.graph.add_vertex(event.clone());

        if g.graph.vertex_count() == 1 {
            return Ok(());
        }

        let edges_to_add = {
            let mut visited_map: HashMap<&VertexId, bool> = g.graph
                .dfs()
                .map(|v| (v, false))
                .collect();

            // Traverse neighbors starting from root vertices
            // using a recursive algorithm.
            //
            // While traversing:
            //
            // If the event happened after the current event,
            // we add an edge between the current event and it 
            // and we continue to the next outbound neighbors.
            //
            // If the event happened before the current event,
            // and there is an edge between the last event
            // and the pushed event, remove the vertex between
            // last and current then add an edge between pushed
            // and current such that the following is true:
            //
            // `last < pushed < current`
            // 
            // If there is no event between between the last and 
            // pushed event, we just add an edge between pushed and
            // current.
            let start_events = g.graph.roots().collect();

            let (edges_to_add, _)  = tail_recurse((vec![], start_events), |(mut edges, events): (Vec<(VertexId, VertexId)>, Vec<&VertexId>)| {
                let edge_count = edges.len() + g.graph.edge_count();
                
                // Exit condition
                if events.len() == 0 {
                    return RecResult::Return((edges, ()));
                }

                // Split into head and tail
                let (h, t) = events.split_at(1);
                let h = h[0];
                let mut t = t.to_vec();
                let is_visited = visited_map.get(h).unwrap();
                
                // Skip visited vertices
                if *is_visited {
                    return RecResult::Continue((edges, t));
                }

                // Skip pushed event
                if pushed == *h {
                    return RecResult::Continue((edges, t));
                } 

                // Mark as visited
                visited_map.insert(h, true);

                // Pushed event happened after stored event with 0 edge count.
                if event_stamp.happened_after(g.graph.fetch(h).unwrap().stamp()) && edge_count == 0 {
                    edges.push((h.clone(), pushed.clone()));
                    return RecResult::Continue((edges, t));
                }

                // Pushed event happened after stored event.
                if event_stamp.happened_after(g.graph.fetch(h).unwrap().stamp()) {
                    if g.graph.out_neighbors_count(h) == 0 {
                        edges.push((h.clone(), pushed.clone()));
                        return RecResult::Continue((edges, t));
                    }
                }

                // Pushed event happened before stored event with 0 edge count.
                if event_stamp.happened_before(g.graph.fetch(h).unwrap().stamp()) && edge_count == 0 {
                    edges.push((pushed.clone(), h.clone()));
                    return RecResult::Continue((edges, t));
                }

                // Pushed event happened before stored event.
                if event_stamp.happened_before(g.graph.fetch(h).unwrap().stamp()) {
                    if g.graph.in_neighbors_count(h) == 0 {
                        edges.push((pushed.clone(), h.clone()));
                        return RecResult::Continue((edges, t));
                    }
                }

                // Append out neighbors to neighbors list
                for v in g.graph.out_neighbors(h) {
                    t.push(v);
                }

                RecResult::Continue((edges, t))
            });
            
            edges_to_add
        };

        // Add the edges to the graph
        edges_to_add
            .iter()
            .for_each(|(o, i)| g.graph.add_edge(o, i).unwrap());

        Ok(())
    }

    /// Returns the highest event in the causal graph
    /// that **does not** belong to the node with the
    /// given `NodeId`.
    pub fn highest(&mut self, node_id: &NodeId) -> Option<Arc<Event>> {
        let graph = &(*self.causal_graph).read().graph;

        graph.fold(None, |v, acc| {
            if acc.is_none() {
                return Some(v.clone());
            }

            // If next happened after accumulated val and it
            // doesn't belong to the given node id, store as
            // new accumulated value.
            if v.stamp().happened_after(acc.clone().unwrap().stamp()) && v.node_id() != *node_id {
                Some(v.clone())
            } else {
                acc
            }
        })
    }

    /// Return the highest event that follows the given
    /// given stamp in the causal graph that **does not**
    /// belong to the node with the given `NodeId`.
    pub fn highest_following(&mut self, node_id: &NodeId, stamp: &Stamp) -> Option<Arc<Event>> {
        let graph = &(*self.causal_graph).read().graph;
        
        graph.fold(None, |v, acc| {
            if acc.is_none() {
                if v.stamp().happened_after(stamp.clone()) && v.node_id() != *node_id {
                    return Some(v.clone());
                } else {
                    return acc;
                }
            }

            // If next happened after accumulated val and it
            // doesn't belong to the given node id, store as
            // new accumulated value.
            if v.stamp().happened_after(acc.clone().unwrap().stamp()) && v.node_id() != *node_id {
                Some(v.clone())
            } else {
                acc
            }
        })
    }

    /// Returns valid candidate sets that can be included
    /// into the total order.
    pub fn fetch_cs(&self) -> Result<Vec<Arc<Mutex<CandidateSet>>>, CGError> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    #[macro_use] use quickcheck::*;
    use super::*;
    use crypto::{Identity, Hash};
    use rand::{thread_rng, Rng};

    #[test]
    /// Causal graph structure:
    ///
    /// A -> B -> C -> D -> E -> F
    /// |
    /// A' -> B' -> C' -> D'
    ///       |
    ///       A''
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

        let s_a = s_a.event();
        let A = Event::Dummy(n1.clone(), None, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let B = Event::Dummy(n2.clone(), None, s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let C = Event::Dummy(n1.clone(), None, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let D = Event::Dummy(n2.clone(), None, s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let E = Event::Dummy(n1, None, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F = Event::Dummy(n2.clone(), None, s_b.clone());

        let s_c = s_c.join(s_a.peek()).event();
        let A_prime = Event::Dummy(n3.clone(), None, s_c.clone());

        let s_c = s_c.event();
        let B_prime = Event::Dummy(n3.clone(), None, s_c.clone());

        let s_c = s_c.event();
        let C_prime = Event::Dummy(n3.clone(), None, s_c.clone());
        let B_second = Event::Dummy(n3.clone(), None, s_c.clone());

        let s_c = s_c.event();
        let D_prime = Event::Dummy(n3, None, s_c);

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

        let mut events: Vec<Arc<Event>> = events
            .iter()
            .map(|e| Arc::new(e.clone()))
            .collect();

        let A = events[0].clone();
        let F = events[5].clone();
        let A_prime = events[6].clone();
        let D_prime = events[9].clone();

        // The causal graph should be the same regardless
        // of the order in which the events are pushed.
        thread_rng().shuffle(&mut events);

        let mut machine = ConsensusMachine::new();

        for e in events {
            machine.push(e).unwrap();
        }

        assert_eq!(machine.highest_following(&n2, &A.stamp()).unwrap(), F);
        assert_eq!(machine.highest_following(&n2, &A_prime.stamp()).unwrap(), D_prime);
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

        let s_a = s_a.event();
        let A = Event::Dummy(n1.clone(), None, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let B = Event::Dummy(n2.clone(), None, s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let C = Event::Dummy(n1.clone(), None, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let D = Event::Dummy(n2.clone(), None, s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let E = Event::Dummy(n1, None, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F = Event::Dummy(n2.clone(), None, s_b.clone());

        let s_c = s_c.join(s_a.peek()).event();
        let A_prime = Event::Dummy(n3.clone(), None, s_c.clone());

        let s_c = s_c.event();
        let B_prime = Event::Dummy(n3.clone(), None, s_c.clone());

        let s_c = s_c.event();
        let C_prime = Event::Dummy(n3.clone(), None, s_c.clone());
        let B_second = Event::Dummy(n3.clone(), None, s_c.clone());

        let s_c = s_c.event();
        let D_prime = Event::Dummy(n3, None, s_c);

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

        let mut events: Vec<Arc<Event>> = events
            .iter()
            .map(|e| Arc::new(e.clone()))
            .collect();

        let F = events[5].clone();

        // The causal graph should be the same regardless
        // of the order in which the events are pushed.
        thread_rng().shuffle(&mut events);

        let mut machine = ConsensusMachine::new();

        for e in events {
            machine.push(e).unwrap();
        }

        assert_eq!(machine.highest(&n2).unwrap(), F);
    }

    quickcheck! {
        /// Causal graph structure:
        ///
        /// A -> B -> C -> D -> E -> F
        /// |
        /// A' -> B' -> C' -> D'
        ///       |
        ///       A''
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

            let s_a = s_a.event();
            let A = Event::Dummy(n1.clone(), Some(Hash::random()), s_a.clone());

            let s_b = s_b.join(s_a.peek()).event();
            let B = Event::Dummy(n2.clone(), Some(Hash::random()), s_b.clone());

            let s_a = s_b.join(s_b.peek()).event();
            let C = Event::Dummy(n1.clone(), Some(Hash::random()), s_a.clone());

            let s_b = s_b.join(s_a.peek()).event();
            let D = Event::Dummy(n2.clone(), Some(Hash::random()), s_b.clone());

            let s_a = s_a.join(s_b.peek()).event();
            let E = Event::Dummy(n1, Some(Hash::random()), s_a.clone());

            let s_b = s_b.join(s_a.peek()).event();
            let F = Event::Dummy(n2.clone(), Some(Hash::random()), s_b.clone());

            let s_c = s_c.join(s_a.peek()).event();
            let A_prime = Event::Dummy(n3.clone(), Some(Hash::random()), s_c.clone());

            let s_c = s_c.event();
            let B_prime = Event::Dummy(n3.clone(), Some(Hash::random()), s_c.clone());

            let s_c = s_c.event();
            let C_prime = Event::Dummy(n3.clone(), Some(Hash::random()), s_c.clone());
            let B_second = Event::Dummy(n3.clone(), Some(Hash::random()), s_c.clone());

            let s_c = s_c.event();
            let D_prime = Event::Dummy(n3, Some(Hash::random()), s_c);

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

            let mut events: Vec<Arc<Event>> = events
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

            // The causal graph should be the same regardless
            // of the order in which the events are pushed.
            thread_rng().shuffle(&mut events);

            let mut machine = ConsensusMachine::new();

            for e in events {
                machine.push(e).unwrap();
            }

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
