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
use hashbrown::{HashMap, HashSet};
use parking_lot::{Mutex, RwLock};
use graphlib::{VertexId, Graph};
use std::sync::Arc;
use recursive::*;
use std::collections::VecDeque;

#[cfg(test)]
use crypto::Hash;

#[cfg(test)]
static mut NODE_LOOKUP: Option<HashMap<Hash, String>> = None;

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

impl ConsensusMachine {
    pub fn new(root_event: Arc<Event>) -> ConsensusMachine {
        ConsensusMachine {
            causal_graph: Arc::new(RwLock::new(CausalGraph::new(root_event))),
            candidate_sets: Vec::new(),
            validators: Vec::new(),
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

        let (edges_to_add, edges_to_remove) = {
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
            // If there is no event between the last and the pushed 
            // event, we just add an edge between pushed and the current.
            let start_events: VecDeque<&VertexId> = g.graph.roots().collect();

            let (edges_to_add, edges_to_remove, _) = tail_recurse((vec![], HashSet::new(), start_events), |(mut edges_to_add, mut edges_to_remove, mut events): (Vec<(VertexId, VertexId)>, HashSet<(VertexId, VertexId)>, VecDeque<&VertexId>)| {
                let edge_count = edges_to_add.len() + g.graph.edge_count();
                let front = events.pop_front();
                
                if let Some(current) = front {
                    let is_visited = visited_map.get(current).unwrap();

                    #[cfg(test)]
                    unsafe {
                        println!("DEBUG CURRENT: {}", NODE_LOOKUP.as_ref().unwrap().get(&g.graph.fetch(current).unwrap().hash().unwrap()).unwrap());
                    }
                    
                    // Skip visited vertices
                    if *is_visited {
                        return RecResult::Continue((edges_to_add, edges_to_remove, events));
                    }

                    // Skip pushed event
                    if pushed == *current {
                        return RecResult::Continue((edges_to_add, edges_to_remove, events));
                    } 

                    // Mark as visited
                    visited_map.insert(current, true);

                    g.graph
                        .out_neighbors(current)
                        // Filter and append out neighbors to neighbors list
                        .filter(|v| !visited_map.get(v).unwrap())
                        .for_each(|v| events.push_front(v));

                    // Pushed event happened after stored event with 0 edge count.
                    if event_stamp.happened_after(g.graph.fetch(current).unwrap().stamp()) && edge_count == 0 {
                        edges_to_add.push((current.clone(), pushed.clone()));
                        println!("DEBUG 1");

                        if g.graph.vertex_count() > 2 {
                            return RecResult::Continue((edges_to_add, edges_to_remove, events));
                        } else {
                            return RecResult::Return((edges_to_add, edges_to_remove, ()));
                        }
                    }

                    // Pushed event happened after stored event.
                    if event_stamp.happened_after(g.graph.fetch(current).unwrap().stamp()) {
                        // In this case we remove any edges between the stored 
                        // event's inbound neighbors and the pushed event.
                        let to_remove: Vec<(VertexId, VertexId)> = g.graph
                            .in_neighbors(current)
                            .map(|n| (n.clone(), pushed.clone()))
                            .collect();

                        edges_to_remove.extend(&to_remove);
                        edges_to_add.push((current.clone(), pushed.clone()));
                        println!("DEBUG 2");

                        return RecResult::Continue((edges_to_add, edges_to_remove, events));
                    }

                    // Pushed event happened before stored event with 0 edge count.
                    if event_stamp.happened_before(g.graph.fetch(current).unwrap().stamp()) && edge_count == 0 {
                        edges_to_add.push((pushed.clone(), current.clone()));
                        println!("DEBUG 3");

                        if g.graph.vertex_count() > 2 {
                            return RecResult::Continue((edges_to_add, edges_to_remove, events));
                        } else {
                            return RecResult::Return((edges_to_add, edges_to_remove, ()));
                        }
                    }

                    // Pushed event happened before stored event.
                    if event_stamp.happened_before(g.graph.fetch(current).unwrap().stamp()) {
                        // // In this case we remove any edges between the stored 
                        // // event's inbound neighbors and the current event that
                        // // have an edge between it and the pushed event.
                        // let to_remove: Vec<(VertexId, VertexId)> = g.graph
                        //     .in_neighbors(current)
                        //     .filter(|n| g.graph.has_edge(n, &pushed) && g.graph.has_edge(n, &current))
                        //     .map(|n| (n.clone(), current.clone()))
                        //     .collect();
    
                        // edges_to_remove.extend(&to_remove);
                        edges_to_add.push((pushed.clone(), current.clone()));
                        println!("DEBUG 4");

                        return RecResult::Return((edges_to_add, edges_to_remove, ()));
                    }

                    RecResult::Continue((edges_to_add, edges_to_remove, events))
                } else {
                    // Exit condition
                    RecResult::Return((edges_to_add, edges_to_remove, ()))
                }
            });
            
            (edges_to_add, edges_to_remove)
        };

        // Add the edges to the graph
        edges_to_add
            .iter()
            .filter(|pair| !edges_to_remove.contains(pair) && pair.0 != pair.1)
            .for_each(|(o, i)| g.graph.add_edge(o, i).unwrap());

        // Remove selected edges
        edges_to_remove
            .iter()
            .for_each(|(o, i)| g.graph.remove_edge(o, i));

        #[cfg(test)]
        unsafe {
            let to_add: Vec<(&String, &String)> = edges_to_add.iter().filter(|pair| !edges_to_remove.contains(pair) && pair.0 != pair.1).map(|(o, i)| (NODE_LOOKUP.as_ref().unwrap().get(&g.graph.fetch(o).unwrap().hash().unwrap()).unwrap(), NODE_LOOKUP.as_ref().unwrap().get(&g.graph.fetch(i).unwrap().hash().unwrap()).unwrap())).collect(); 
            let to_remove: Vec<(&String, &String)> = edges_to_remove.iter().map(|(o, i)| (NODE_LOOKUP.as_ref().unwrap().get(&g.graph.fetch(o).unwrap().hash().unwrap()).unwrap(), NODE_LOOKUP.as_ref().unwrap().get(&g.graph.fetch(i).unwrap().hash().unwrap()).unwrap())).collect(); 
        
            println!("DEBUG EDGES TO ADD: {:?}", to_add);
            println!("DEBUG EDGES TO REMOVE: {:?}", to_remove);
        }    

        Ok(())
    }

    /// Returns the highest event in the causal graph
    /// that **does not** belong to the node with the
    /// given `NodeId`.
    pub fn highest(&mut self, node_id: &NodeId) -> Option<Arc<Event>> {
        let graph = &(*self.causal_graph).read().graph;
        // let mut highest_map: HashMap<&VertexId, usize> = HashMap::with_capacity(graph.vertex_count());

        // let start_events: Vec<&VertexId> = graph.roots().collect();

        // if start_events.is_empty() {
        //     return None;
        // }

        // // Start by finding the highest events of all branches.
        // let (highest, _) = tail_recurse((None, start_events), |(acc, events): (Option<&VertexId>, Vec<&VertexId>)| {
        //     // Exit condition
        //     if events.is_empty() {
        //         return RecResult::Return((acc, events));
        //     }

        //     let (h, t) = events.split_at(1);
        //     let h = h[0];
        //     let mut t = t.to_vec();

        //     if acc.is_none() {
        //         return RecResult::Continue((Some(&h), t));
        //     }

        //     let cur = graph.fetch(acc.unwrap()).unwrap();

        //     let e = graph.fetch(h).unwrap();
        //     let s = e.stamp();

        //     // If next happened after accumulated val and it
        //     // doesn't belong to the given node id, store as
        //     // new accumulated value.
        //     if s.happened_after(cur.stamp()) && e.node_id() != *node_id {
        //         RecResult::Continue((Some(&h), t))
        //     } else {
        //         RecResult::Continue((acc, t))
        //     }
        // });

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

        // if let Some(highest) = highest {
        //     Some(graph.fetch(highest).unwrap().clone())
        // } else {
        //     None
        // }
    }

    /// Return the highest event that follows the given
    /// given stamp in the causal graph that **does not**
    /// belong to the node with the given `NodeId`.
    pub fn highest_following(&mut self, node_id: &NodeId, stamp: &Stamp) -> Option<Arc<Event>> {
        let graph = &(*self.causal_graph).read().graph;

        // // Filter concurrent roots
        // let start_events = graph
        //     .roots()
        //     .filter(|v| v.stamp().concurrent(stamp))
        //     .collect();

        // if start_events.is_empty() {
        //     return None;
        // }
        
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

    /// Returns true if the second event happened exactly after the first event.
    pub(crate) fn is_direct_follower(&self, event1: Arc<Event>, event2: Arc<Event>) -> bool {
        self.causal_graph.read().is_direct_follower(event1, event2)
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
        let E = Event::Dummy(n1, E_hash.clone(), Some(D_hash), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F_hash = Hash::random();
        let F = Event::Dummy(n2.clone(), F_hash, Some(E_hash), s_b.clone());

        let events = vec![
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

        let mut machine = ConsensusMachine::new(A.clone());

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
        let E = Event::Dummy(n1, E_hash.clone(), Some(D_hash), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F_hash = Hash::random();
        let F = Event::Dummy(n2.clone(), F_hash, Some(E_hash), s_b.clone());

        let events = vec![
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

        // The causal graph should be the same regardless
        // of the order in which the events are pushed.
        thread_rng().shuffle(&mut events);

        let mut machine = ConsensusMachine::new(A.clone());

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
        ///       B''
        fn graph_assembly() -> bool {
            let i1 = Identity::new();
            let i2 = Identity::new();
            let i3 = Identity::new();
            let i4 = Identity::new();
            let n1 = NodeId(*i1.pkey());
            let n2 = NodeId(*i2.pkey());
            let n3 = NodeId(*i3.pkey());
            let n4 = NodeId(*i4.pkey());
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
            let E = Event::Dummy(n1, E_hash.clone(), Some(D_hash), s_a.clone());

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

            unsafe {
                NODE_LOOKUP = Some(HashMap::new());

                NODE_LOOKUP.as_mut().unwrap().insert(A.hash().unwrap(), "A".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(B.hash().unwrap(), "B".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(C.hash().unwrap(), "C".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(D.hash().unwrap(), "D".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(E.hash().unwrap(), "E".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(F.hash().unwrap(), "F".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(A_prime.hash().unwrap(), "A prime".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(B_prime.hash().unwrap(), "B prime".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(C_prime.hash().unwrap(), "C prime".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(D_prime.hash().unwrap(), "D prime".to_string());
                NODE_LOOKUP.as_mut().unwrap().insert(B_second.hash().unwrap(), "B second".to_string());
            }

            // The causal graph should be the same regardless
            // of the order in which the events are pushed.
            thread_rng().shuffle(&mut events);

            let mut machine = ConsensusMachine::new(A.clone());

            for e in events {
                unsafe {
                    println!("DEBUG PUSHED: {}", NODE_LOOKUP.as_ref().unwrap().get(&e.hash().unwrap()).unwrap());
                }
                
                machine.push(e).unwrap();
            }

            assert!(!machine.causal_graph.read().graph.is_cyclic());
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
