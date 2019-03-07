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
use parking_lot::{Mutex, RwLock};
use petgraph::graph::NodeIndex;
use petgraph::visit::Dfs;
use petgraph::Direction;
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
    causal_graph: Arc<RwLock<CausalGraph>>,
    graph_roots: Vec<NodeIndex>,
    candidate_sets: Vec<Arc<Mutex<CandidateSet>>>,
    validators: Vec<Arc<Mutex<ValidatorState>>>,
}

impl ConsensusMachine {
    pub fn new() -> ConsensusMachine {
        ConsensusMachine {
            causal_graph: Arc::new(RwLock::new(CausalGraph::new())),
            graph_roots: Vec::new(),
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
        let mut graph = self.causal_graph.write();
        let event_stamp = event.stamp();

        if graph.any(|e| e == event) {
            return Err(CGError::AlreadyInCG);
        }

        // If the causal graph is empty,
        // just append a new node and return.
        if graph.empty() {
            let idx = graph.0.add_node(event);

            // Mark as root
            self.graph_roots.push(idx);
            return Ok(());
        }

        // Append node to graph
        let pushed_idx = graph.0.add_node(event.clone());

        if graph.0.edge_count() == 0 {
            let mut roots = self.graph_roots.clone();

            // Attempt to create the first edge in the graph
            let mut dfs = Dfs::empty(&graph.0);

            while let Some(r) = roots.pop() {
                dfs.move_to(r);

                while let Some(i) = dfs.next(&graph.0) {
                    let edge_count = graph.0.edge_count();

                    println!("DEBUG I: {:?}", i);

                    // Skip pushed event
                    if event == graph.0[i] {
                        continue;
                    }

                    // Pushed event happened after stored event with 0 edge count.
                    if event_stamp.happened_after((*graph.0[i]).stamp()) && edge_count == 0 {
                        graph.0.add_edge(i, pushed_idx, ());
                        continue;
                    }

                    // Pushed event happened after stored event.
                    if event_stamp.happened_after((*graph.0[i]).stamp()) {
                        let mut n = graph.0.neighbors_directed(i, Direction::Outgoing);
                        let mut neighbors_len = 0;

                        while let Some(_) = n.next() {
                            neighbors_len += 1;
                        }

                        if neighbors_len == 0 {
                            graph.0.add_edge(i, pushed_idx, ());
                            continue;
                        }
                    }

                    // Pushed event happened before stored event with 0 edge count.
                    if event_stamp.happened_before((*graph.0[i]).stamp()) && edge_count == 0 {
                        graph.0.add_edge(pushed_idx, i, ());
                        self.graph_roots = vec![pushed_idx];
                        continue;
                    }

                    // Pushed event happened before stored event.
                    if event_stamp.happened_before((*graph.0[i]).stamp()) {
                        let mut n = graph.0.neighbors_directed(i, Direction::Incoming);
                        let mut neighbors_len = 0;

                        while let Some(_) = n.next() {
                            neighbors_len += 1;
                        }

                        if neighbors_len == 0 {
                            graph.0.add_edge(pushed_idx, i, ());

                            if is_root(&self.graph_roots, &i) {
                                // Replace old root with new one
                                let mut new_roots: Vec<NodeIndex> = self.graph_roots
                                    .iter()
                                    .filter(|j| *j != &i)
                                    .map(|x| x.clone())
                                    .collect();

                                new_roots.push(i);
                               
                               self.graph_roots = new_roots;
                            } else {
                                self.graph_roots.push(i);
                            }

                            continue;
                        }

                        // Event has no relationship to any other events 
                        // so we just update the roots vector.
                        self.graph_roots.push(i);
                    }
                }
            }
        } else {
            let mut roots = self.graph_roots.clone();

            // Create edges based on the causal relationships
            // of the events that are placed in the graph.
            let mut dfs = Dfs::empty(&graph.0);

            while let Some(r) = roots.pop() {
                dfs.move_to(r);

                while let Some(i) = dfs.next(&graph.0) {
                    // Skip pushed event
                    if event == graph.0[i] {
                        continue;
                    }

                    // Pushed event happened after stored event.
                    if event_stamp.happened_after((*graph.0[i]).stamp()) {
                        let mut n = graph.0.neighbors_directed(i, Direction::Outgoing);
                        let mut neighbors: Vec< NodeIndex> = Vec::new();

                        // Fetch neighbors and their indexes
                        while let Some(i) = n.next() {
                            neighbors.push(i);
                        }

                        // Add edge and continue if there aren't
                        // any outgoing neighbors.
                        if neighbors.len() == 0 {
                            graph.0.add_edge(i, pushed_idx, ());
                            continue;
                        }

                        for idx in neighbors {
                            traverse_and_add_edge(&mut graph, event.clone(), idx, Direction::Outgoing);
                        }

                        continue;
                    }

                    // Pushed event happened before stored event.
                    if event_stamp.happened_before((*graph.0[i]).stamp()) {
                        let mut n = graph.0.neighbors_directed(i, Direction::Incoming);
                        let mut neighbors: Vec<NodeIndex> = Vec::new();

                        // Fetch neighbors indexes
                        while let Some(i) = n.next() {
                            neighbors.push(i);
                        }

                        // Add edge and continue if there aren't
                        // any incoming neighbors.
                        if neighbors.len() == 0 {
                            graph.0.add_edge(pushed_idx, i, ());

                            if is_root(&self.graph_roots, &i) {
                                // Replace old root with new one
                                let mut new_roots: Vec<NodeIndex> = self.graph_roots
                                    .iter()
                                    .filter(|j| *j != &i)
                                    .map(|x| x.clone())
                                    .collect();

                                new_roots.push(i);
                                
                                self.graph_roots = new_roots;
                            } else {
                                self.graph_roots.push(i);
                            }

                            continue;
                        }

                        for idx in neighbors {
                            traverse_and_add_edge(&mut graph, event.clone(), idx, Direction::Incoming);
                        }

                        continue;
                    }

                    // Event has no relationship to any other events 
                    // so we just update the roots vector.
                    self.graph_roots.push(i);
                }
            }
        }

        Ok(())
    }

    /// Returns the highest event in the causal graph
    /// that **does not** belong to the node with the
    /// given `NodeId`.
    pub fn highest(&self, node_id: &NodeId) -> Option<Arc<Event>> {
        let graph = &(*self.causal_graph).read().0;

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
            if (*graph[i]).stamp().happened_after((*graph[acc_i]).stamp())
                && (*graph[i]).node_id() != *node_id
            {
                acc = Some(i);
            }
        }

        if let Some(i) = acc {
            Some(graph[i].clone())
        } else {
            None
        }
    }

    /// Return the highest event that follows the given
    /// given stamp in the causal graph that **does not**
    /// belong to the node with the given `NodeId`.
    pub fn highest_following(
        &self,
        node_id: &NodeId,
        stamp: &Stamp,
    ) -> Option<Arc<Event>> {
        let graph = &(*self.causal_graph).read().0;

        let mut dfs = Dfs::empty(graph);
        let mut acc = None;

        while let Some(i) = dfs.next(graph) {
            if acc.is_none() {
                if (*graph[i]).stamp().happened_after(stamp.clone())
                    && (*graph[i]).node_id() != *node_id
                {
                    acc = Some(i);
                }

                continue;
            }

            let acc_i = acc.unwrap();

            // If next happened after accumulated val and it
            // doesn't belong to the given node id, store as
            // new accumulated value.
            if (*graph[i]).stamp().happened_after((*graph[acc_i]).stamp())
                && (*graph[i]).node_id() != *node_id
            {
                acc = Some(i);
            }
        }

        if let Some(i) = acc {
            Some(graph[i].clone())
        } else {
            None
        }
    }

    /// Returns valid candidate sets that can be included
    /// into the total order.
    pub fn fetch_cs(&self) -> Result<Vec<Arc<Mutex<CandidateSet>>>, CGError> {
        unimplemented!();
    }   
}

fn is_root(roots: &[NodeIndex], idx: &NodeIndex) -> bool {
    roots
        .iter()
        .any(|i| i == idx)
}

/// Traverses the neighbors of the node with the given start
/// index in the given `Direction`. An edge is added between
/// the event and the other already placed events based on
/// their causal relationship.
fn traverse_and_add_edge(graph: &mut CausalGraph, event: Arc<Event>, start_idx: NodeIndex, direction: Direction) {
    unimplemented!();
} 

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use crypto::Identity;

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
        let A = Event::Dummy(n1.clone(), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let B = Event::Dummy(n2.clone(), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let C = Event::Dummy(n1.clone(), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let D = Event::Dummy(n2.clone(), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let E = Event::Dummy(n1, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F = Event::Dummy(n2.clone(), s_b.clone());

        let s_c = s_c.join(s_a.peek()).event();
        let A_prime = Event::Dummy(n3.clone(), s_c.clone());

        let s_c = s_c.event();
        let B_prime = Event::Dummy(n3.clone(), s_c.clone());

        let s_c = s_c.event();
        let C_prime = Event::Dummy(n3.clone(), s_c.clone());
        let B_second = Event::Dummy(n3.clone(), s_c.clone());

        let s_c = s_c.event();
        let D_prime = Event::Dummy(n3, s_c);

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

        println!("DEBUG {:?}", machine);

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
        let A = Event::Dummy(n1.clone(), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let B = Event::Dummy(n2.clone(), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let C = Event::Dummy(n1.clone(), s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let D = Event::Dummy(n2.clone(), s_b.clone());

        let s_a = s_a.join(s_b.peek()).event();
        let E = Event::Dummy(n1, s_a.clone());

        let s_b = s_b.join(s_a.peek()).event();
        let F = Event::Dummy(n2.clone(), s_b.clone());

        let s_c = s_c.join(s_a.peek()).event();
        let A_prime = Event::Dummy(n3.clone(), s_c.clone());

        let s_c = s_c.event();
        let B_prime = Event::Dummy(n3.clone(), s_c.clone());

        let s_c = s_c.event();
        let C_prime = Event::Dummy(n3.clone(), s_c.clone());
        let B_second = Event::Dummy(n3.clone(), s_c.clone());

        let s_c = s_c.event();
        let D_prime = Event::Dummy(n3, s_c);

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
}