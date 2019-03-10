// Copyright 2019 Octavian Oncescu

use crate::edge::Edge;
use crate::vertex_id::VertexId;
use hashbrown::HashMap;
use std::ptr;

#[derive(Clone, Debug, PartialEq)]
pub enum GraphErr {
    NoSuchVertex,
}

#[derive(Debug)]
pub struct Graph<T, M> {
    vertices: HashMap<Box<VertexId>, (T, Box<VertexId>)>,
    edges: Vec<Edge<M>>,
    inbound_table: HashMap<Box<VertexId>, Vec<Box<VertexId>>>,
    outbound_table: HashMap<Box<VertexId>, Vec<Box<VertexId>>>,
}

impl<T, M> Graph<T, M> {
    pub fn new() -> Graph<T, M> {
        Graph {
            vertices: HashMap::new(),
            edges: Vec::new(),
            inbound_table: HashMap::new(),
            outbound_table: HashMap::new(),
        }
    }

    /// Adds a new vertex to the graph and returns the id
    /// of the added vertex.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    /// let id = graph.add_vertex(1);
    ///
    /// assert_eq!(graph.fetch(&id).unwrap(), &1);
    /// ```
    pub fn add_vertex(&mut self, item: T) -> VertexId {
        let id = VertexId::random();
        let id_ptr = Box::new(id.clone()); 
        self.vertices.insert(id_ptr.clone(), (item, id_ptr.clone()));
        id
    }

    /// Attempts to place a new edge in the graph.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::{Graph, GraphErr, VertexId};
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    ///
    /// // Id of vertex that is not place in the graph
    /// let id = VertexId::random();
    ///
    /// let v1 = graph.add_vertex(1);
    /// let v2 = graph.add_vertex(2);
    ///
    /// // Succeeds on adding an edge between
    /// // existing vertices.
    /// assert_eq!(graph.add_edge(&v1, &v2), Ok(()));
    ///
    /// // Fails on adding an edge between an
    /// // existing vertex and a non-existing one.
    /// assert_eq!(graph.add_edge(&v1, &id), Err(GraphErr::NoSuchVertex));
    /// ```
    pub fn add_edge(&mut self, a: &VertexId, b: &VertexId) -> Result<(), GraphErr> {
        let a_prime = self.vertices.get(a);
        let b_prime = self.vertices.get(b);

        // Check vertices existence
        match (a_prime, b_prime) {
            (Some((_, id_ptr1)), Some((_, id_ptr2))) => {
                let edge = Edge::<M>::new(id_ptr1.clone(), id_ptr2.clone(), None);

                // Push edge
                self.edges.push(edge);

                // Update outbound table
                match self.outbound_table.get(id_ptr1) {
                    Some(outbounds) => {
                        let mut outbounds = outbounds.clone();
                        outbounds.push(id_ptr2.clone());

                        self.outbound_table.insert(Box::new(*a), outbounds);
                    }
                    None => {
                        self.outbound_table.insert(Box::new(*a), vec![id_ptr2.clone()]);
                    }
                }

                // Update inbound table
                match self.inbound_table.get(id_ptr2) {
                    Some(inbounds) => {
                        let mut inbounds = inbounds.clone();
                        inbounds.push(id_ptr1.clone());

                        self.inbound_table.insert(Box::new(*b), inbounds);
                    }
                    None => {
                        self.inbound_table.insert(Box::new(*b), vec![id_ptr1.clone()]);
                    }
                }

                Ok(())
            }
            _ => Err(GraphErr::NoSuchVertex),
        }
    }

    /// Checks whether or not exists an edge between
    /// the vertices with the given ids.
    /// 
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    ///
    /// let v1 = graph.add_vertex(1);
    /// let v2 = graph.add_vertex(2);
    /// let v3 = graph.add_vertex(3);
    /// 
    /// graph.add_edge(&v1, &v2).unwrap();
    /// 
    /// assert!(graph.has_edge(&v1, &v2));
    /// assert!(!graph.has_edge(&v2, &v3));
    /// ```
    pub fn has_edge(&self, a: &VertexId, b: &VertexId) -> bool {
        match self.outbound_table.get(a) {
            Some(outbounds) => {
                outbounds
                    .iter()
                    .any(|v| *b == **v)
            },
            None => false
        }
    }

    /// Returns the total number of edges that are listed
    /// in the graph.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    ///
    /// let v1 = graph.add_vertex(0);
    /// let v2 = graph.add_vertex(1);
    /// let v3 = graph.add_vertex(2);
    /// let v4 = graph.add_vertex(3);
    ///
    /// graph.add_edge(&v1, &v2).unwrap();
    /// graph.add_edge(&v2, &v3).unwrap();
    /// graph.add_edge(&v3, &v4).unwrap();
    ///
    /// assert_eq!(graph.edge_count(), 3);
    /// ```
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns the number of vertices that are placed in
    /// the graph.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    ///
    /// graph.add_vertex(1);
    /// graph.add_vertex(2);
    /// graph.add_vertex(3);
    ///
    /// assert_eq!(graph.vertex_count(), 3);
    /// ```
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Attempts to fetch an item placed in the graph
    /// using the provided `VertexId`.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    /// let id = graph.add_vertex(1);
    ///
    /// assert_eq!(graph.fetch(&id), Some(&1));
    /// ```
    pub fn fetch(&self, id: &VertexId) -> Option<&T> {
        let result = self.vertices.get(id);

        match result {
            Some((result, _)) => Some(result),
            None => None,
        }
    }

    /// Returns the total count of neighboring vertices
    /// of the vertex with the given id.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    ///
    /// let v1 = graph.add_vertex(0);
    /// let v2 = graph.add_vertex(1);
    /// let v3 = graph.add_vertex(2);
    /// let v4 = graph.add_vertex(3);
    ///
    /// graph.add_edge(&v1, &v2).unwrap();
    /// graph.add_edge(&v3, &v1).unwrap();
    /// graph.add_edge(&v1, &v4).unwrap();
    ///
    /// assert_eq!(graph.neighbors_count(&v1), 3);
    /// ```
    pub fn neighbors_count(&self, id: &VertexId) -> usize {
        self.in_neighbors_count(id) + self.out_neighbors_count(id)
    }

    /// Returns the total count of inbound neighboring
    /// vertices of the vertex with the given id.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    ///
    /// let v1 = graph.add_vertex(0);
    /// let v2 = graph.add_vertex(1);
    /// let v3 = graph.add_vertex(2);
    /// let v4 = graph.add_vertex(3);
    ///
    /// graph.add_edge(&v1, &v2).unwrap();
    /// graph.add_edge(&v3, &v1).unwrap();
    /// graph.add_edge(&v1, &v4).unwrap();
    ///
    /// assert_eq!(graph.in_neighbors_count(&v1), 1);
    /// ```
    pub fn in_neighbors_count(&self, id: &VertexId) -> usize {
        match self.inbound_table.get(id) {
            Some(ins) => ins.len(),
            None => 0,
        }
    }

    /// Returns the total count of outbound neighboring
    /// vertices of the vertex with the given id.
    ///
    /// ## Example
    /// ```rust
    /// use graphlib::Graph;
    ///
    /// let mut graph: Graph<usize, ()> = Graph::new();
    ///
    /// let v1 = graph.add_vertex(0);
    /// let v2 = graph.add_vertex(1);
    /// let v3 = graph.add_vertex(2);
    /// let v4 = graph.add_vertex(3);
    ///
    /// graph.add_edge(&v1, &v2).unwrap();
    /// graph.add_edge(&v3, &v1).unwrap();
    /// graph.add_edge(&v1, &v4).unwrap();
    ///
    /// assert_eq!(graph.out_neighbors_count(&v1), 2);
    /// ```
    pub fn out_neighbors_count(&self, id: &VertexId) -> usize {
        match self.outbound_table.get(id) {
            Some(outs) => outs.len(),
            None => 0,
        }
    }

    // pub fn in_neighbors(&self, id: &VertexId) -> impl Iterator<Item = &T> {
    //     unimplemented!();
    // }

    // pub fn dfs() -> impl Iterator<Item = &'g T> {
    //     unimplemented!();
    // }

    // pub fn bfs() -> impl Iterator<Item = &'g T> {
    //     unimplemented!();
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
}
