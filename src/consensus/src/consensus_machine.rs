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

                    println!("DEBUG I1: {:?}", i);

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
                                let mut new_roots: Vec<NodeIndex> = self
                                    .graph_roots
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

                    println!("DEBUG I2 {:?}", i);

                    // Pushed event happened after stored event.
                    if event_stamp.happened_after((*graph.0[i]).stamp()) {
                        let mut n = graph.0.neighbors_directed(i, Direction::Outgoing);
                        let mut neighbors: Vec<NodeIndex> = Vec::new();

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
                            let new_roots = traverse_and_add_edge(
                                &mut graph,
                                self.graph_roots.clone(),
                                event.clone(),
                                pushed_idx,
                                idx,
                                Direction::Outgoing,
                            );
                            self.graph_roots = new_roots;
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
                                let mut new_roots: Vec<NodeIndex> = self
                                    .graph_roots
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
                            let new_roots = traverse_and_add_edge(
                                &mut graph,
                                self.graph_roots.clone(),
                                event.clone(),
                                pushed_idx,
                                idx,
                                Direction::Incoming,
                            );
                            self.graph_roots = new_roots;
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
    pub fn highest_following(&self, node_id: &NodeId, stamp: &Stamp) -> Option<Arc<Event>> {
        let graph = &(*self.causal_graph).read().0;
        let mut roots = self.graph_roots.clone();

        let mut dfs = Dfs::empty(graph);
        let mut acc = None;

        while let Some(r) = roots.pop() {
            dfs.move_to(r);

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
    roots.iter().any(|i| i == idx)
}

/// Traverses the neighbors of the node with the given start
/// index in the given `Direction`. An edge is added between
/// the event and the other already placed events based on
/// their causal relationship.
///
/// This function will return the updated graph roots vector.
fn traverse_and_add_edge(
    graph: &mut CausalGraph,
    graph_roots: Vec<NodeIndex>,
    event: Arc<Event>,
    event_idx: NodeIndex,
    start_idx: NodeIndex,
    direction: Direction,
) -> Vec<NodeIndex> {
    let mut start_indexes: Vec<NodeIndex> = vec![start_idx];
    let mut graph_roots = graph_roots;

    let mut unvisited_nodes: Vec<NodeIndex> = Vec::new();

    for idx in graph.0.node_indices() {
        unvisited_nodes.push(idx);
    }

    // Such recursion with non-recursive code, much fun
    while let Some(start_idx) = start_indexes.pop() {
        let mut last_idx: Option<NodeIndex> = None;
        let mut idx = start_idx;

        println!("Start idx: {:?}", start_idx);

        loop {
            if unvisited_nodes.is_empty() {
                break;
            }

            let is_unvisited = unvisited_nodes
                .iter()
                .any(|i| *graph.0[*i] == *graph.0[idx]);

            if !is_unvisited {
                continue;
            }

            if Some(idx) == last_idx {
                break;
            }

            unvisited_nodes = unvisited_nodes
                .iter()
                .filter(|i| *graph.0[**i] != *graph.0[idx])
                .map(|i| i.clone())
                .collect();

            // if *graph.0[idx] == *event {
            //     continue;
            // }

            println!("Current idx: {:?}", idx);

            // Try to place event between last and current index
            if let Some(last_idx) = last_idx {
                let last_node = graph.0[last_idx].clone();
                let cur_node = graph.0[idx].clone();

                println!("DEBUG 3");

                //  The event is between the last node and current node:
                //  CURRENT > EVENT > LAST
                if event.stamp().happened_before(last_node.stamp())
                    && event.stamp().happened_after(cur_node.stamp())
                {
                    let edge_idx = graph.0.find_edge(idx, last_idx);

                    match edge_idx {
                        Some(idx) => {
                            graph.0.remove_edge(idx);
                        }
                        _ => {} // Do nothing
                    };

                    graph.0.add_edge(event_idx, last_idx, ());
                    graph.0.add_edge(idx, event_idx, ());

                    println!("DEBUG 1");

                    break;
                }

                // The event is between the last node and the current node
                // LAST > EVENT > CURRENT
                if event.stamp().happened_after(last_node.stamp())
                    && event.stamp().happened_before(cur_node.stamp())
                {
                    let edge_idx = graph.0.find_edge(idx, last_idx);

                    match edge_idx {
                        Some(idx) => {
                            graph.0.remove_edge(idx);
                        }
                        _ => {} // Do nothing
                    };

                    graph.0.add_edge(last_idx, event_idx, ());
                    graph.0.add_edge(event_idx, idx, ());

                    println!("DEBUG 5");

                    break;
                }

                // The event happened before the current event
                // EVENT > CURRENT
                if event.stamp().happened_before(cur_node.stamp()) {
                    graph.0.add_edge(event_idx, idx, ());
                    break;
                };

                // The event happened after the current event
                // EVENT > CURRENT
                if event.stamp().happened_after(cur_node.stamp()) {
                    graph.0.add_edge(idx, event_idx, ());
                    break;
                };

                if event.stamp().concurrent(last_node.stamp()) {
                    println!("DEBUG 2");
                    break;
                }

                if event.stamp().eq(&cur_node.stamp()) {
                    let out_neighbors: Vec<NodeIndex> = graph
                        .0
                        .neighbors_directed(idx, Direction::Outgoing)
                        .collect();
                    let in_neighbors: Vec<NodeIndex> = graph
                        .0
                        .neighbors_directed(idx, Direction::Incoming)
                        .collect();

                    // Attach stamp to cur stamp's neighbors
                    for idx in out_neighbors {
                        let edge_idx = graph.0.find_edge(event_idx, idx);

                        if let Some(_) = edge_idx {
                            // Do nothing
                        } else {
                            graph.0.add_edge(event_idx, idx, ());
                        }
                    }

                    for idx in in_neighbors {
                        let edge_idx = graph.0.find_edge(idx, event_idx);

                        if let Some(_) = edge_idx {
                            // Do nothing
                        } else {
                            graph.0.add_edge(idx, event_idx, ());
                        }
                    }

                    println!("DEBUG 4");
                    break;
                }
            }

            last_idx = Some(idx);

            let mut n = graph.0.neighbors_directed(idx, direction);
            let mut neighbors: Vec<NodeIndex> = Vec::new();

            // Fetch neighbors indexes
            while let Some(i) = n.next() {
                neighbors.push(i);
            }

            println!("DEBUG NEIGHBORS: {:?}, LAST_IDX: {:?}", neighbors, last_idx);

            // use std::{thread, time};

            // let ten_millis = time::Duration::from_millis(300);
            // let now = time::Instant::now();

            // thread::sleep(ten_millis);

            // No neighbors which means this will
            // be a root node in the graph.
            if neighbors.len() == 0 {
                // Replace old root with new one
                let mut new_roots: Vec<NodeIndex> = graph_roots
                    .iter()
                    .filter(|j| *j != &idx)
                    .map(|x| x.clone())
                    .collect();

                new_roots.push(event_idx);

                graph_roots = new_roots;

                graph.0.add_edge(event_idx, idx, ());
                break;
            } else {
                let (h, t) = neighbors.split_at(1);
                start_indexes.extend_from_slice(&t);
                start_indexes.sort_unstable();
                start_indexes.dedup();

                println!("DEBUG START IDXS: {:?}, {:?}", start_indexes, h);
                idx = h[0];
            }
        }
    }

    graph_roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;
    use rand::{thread_rng, Rng};

    // #[test]
    // /// Causal graph structure:
    // ///
    // /// A -> B -> C -> D -> E -> F
    // /// |
    // /// A' -> B' -> C' -> D'
    // ///       |
    // ///       A''
    // ///
    // /// The intended result for calling the function on A should be F
    // /// and the intended result for A' should be D'.
    // fn highest_following() {
    //     let i1 = Identity::new();
    //     let i2 = Identity::new();
    //     let i3 = Identity::new();
    //     let n1 = NodeId(*i1.pkey());
    //     let n2 = NodeId(*i2.pkey());
    //     let n3 = NodeId(*i3.pkey());
    //     let seed = Stamp::seed();
    //     let (s_a, s_b) = seed.fork();
    //     let (s_b, s_c) = s_b.fork();

    //     let s_a = s_a.event();
    //     let A = Event::Dummy(n1.clone(), s_a.clone());

    //     let s_b = s_b.join(s_a.peek()).event();
    //     let B = Event::Dummy(n2.clone(), s_b.clone());

    //     let s_a = s_a.join(s_b.peek()).event();
    //     let C = Event::Dummy(n1.clone(), s_a.clone());

    //     let s_b = s_b.join(s_a.peek()).event();
    //     let D = Event::Dummy(n2.clone(), s_b.clone());

    //     let s_a = s_a.join(s_b.peek()).event();
    //     let E = Event::Dummy(n1, s_a.clone());

    //     let s_b = s_b.join(s_a.peek()).event();
    //     let F = Event::Dummy(n2.clone(), s_b.clone());

    //     let s_c = s_c.join(s_a.peek()).event();
    //     let A_prime = Event::Dummy(n3.clone(), s_c.clone());

    //     let s_c = s_c.event();
    //     let B_prime = Event::Dummy(n3.clone(), s_c.clone());

    //     let s_c = s_c.event();
    //     let C_prime = Event::Dummy(n3.clone(), s_c.clone());
    //     let B_second = Event::Dummy(n3.clone(), s_c.clone());

    //     let s_c = s_c.event();
    //     let D_prime = Event::Dummy(n3, s_c);

    //     let events = vec![
    //         A,
    //         B,
    //         C,
    //         D,
    //         E,
    //         F,
    //         A_prime,
    //         B_prime,
    //         C_prime,
    //         D_prime,
    //         B_second
    //     ];

    //     let mut events: Vec<Arc<Event>> = events
    //         .iter()
    //         .map(|e| Arc::new(e.clone()))
    //         .collect();

    //     let A = events[0].clone();
    //     let F = events[5].clone();
    //     let A_prime = events[6].clone();
    //     let D_prime = events[9].clone();

    //     // The causal graph should be the same regardless
    //     // of the order in which the events are pushed.
    //     thread_rng().shuffle(&mut events);

    //     let mut machine = ConsensusMachine::new();

    //     for e in events {
    //         machine.push(e).unwrap();
    //     }

    //     println!("DEBUG {:?}", machine);

    //     assert_eq!(machine.highest_following(&n2, &A.stamp()).unwrap(), F);
    //     assert_eq!(machine.highest_following(&n2, &A_prime.stamp()).unwrap(), D_prime);
    // }

    // #[test]
    // /// Causal graph structure:
    // ///
    // /// A -> B -> C -> D -> E -> F
    // /// |
    // /// A' -> B' -> C' -> D'
    // ///       |
    // ///       A''
    // ///
    // /// The intended result for calling the function should be F.
    // fn highest() {
    //     let i1 = Identity::new();
    //     let i2 = Identity::new();
    //     let i3 = Identity::new();
    //     let n1 = NodeId(*i1.pkey());
    //     let n2 = NodeId(*i2.pkey());
    //     let n3 = NodeId(*i3.pkey());
    //     let seed = Stamp::seed();
    //     let (s_a, s_b) = seed.fork();
    //     let (s_b, s_c) = s_b.fork();

    //     let s_a = s_a.event();
    //     let A = Event::Dummy(n1.clone(), s_a.clone());

    //     let s_b = s_b.join(s_a.peek()).event();
    //     let B = Event::Dummy(n2.clone(), s_b.clone());

    //     let s_a = s_a.join(s_b.peek()).event();
    //     let C = Event::Dummy(n1.clone(), s_a.clone());

    //     let s_b = s_b.join(s_a.peek()).event();
    //     let D = Event::Dummy(n2.clone(), s_b.clone());

    //     let s_a = s_a.join(s_b.peek()).event();
    //     let E = Event::Dummy(n1, s_a.clone());

    //     let s_b = s_b.join(s_a.peek()).event();
    //     let F = Event::Dummy(n2.clone(), s_b.clone());

    //     let s_c = s_c.join(s_a.peek()).event();
    //     let A_prime = Event::Dummy(n3.clone(), s_c.clone());

    //     let s_c = s_c.event();
    //     let B_prime = Event::Dummy(n3.clone(), s_c.clone());

    //     let s_c = s_c.event();
    //     let C_prime = Event::Dummy(n3.clone(), s_c.clone());
    //     let B_second = Event::Dummy(n3.clone(), s_c.clone());

    //     let s_c = s_c.event();
    //     let D_prime = Event::Dummy(n3, s_c);

    //     let events = vec![
    //         A,
    //         B,
    //         C,
    //         D,
    //         E,
    //         F,
    //         A_prime,
    //         B_prime,
    //         C_prime,
    //         D_prime,
    //         B_second
    //     ];

    //     let mut events: Vec<Arc<Event>> = events
    //         .iter()
    //         .map(|e| Arc::new(e.clone()))
    //         .collect();

    //     let F = events[5].clone();

    //     // The causal graph should be the same regardless
    //     // of the order in which the events are pushed.
    //     thread_rng().shuffle(&mut events);

    //     let mut machine = ConsensusMachine::new();

    //     for e in events {
    //         machine.push(e).unwrap();
    //     }

    //     assert_eq!(machine.highest(&n2).unwrap(), F);
    // }
}
