// Copyright 2019 Octavian Oncescu

use crate::edge::Edge;
use crate::vertex_id::VertexId;
use hashbrown::HashMap;

#[derive(Clone, Debug)]
pub enum GraphErr {
    NoSuchVertex
}

#[derive(Debug)]
pub struct Graph<T, M> {
    vertices: HashMap<VertexId, (T, *const VertexId)>,
    edges: Vec<Edge<M>>,
    inbound_table: HashMap<VertexId, Vec<*const VertexId>>,
    outbound_table: HashMap<VertexId, Vec<*const VertexId>> 
}

impl<T, M> Graph<T, M> {
    pub fn new() -> Graph<T, M> {
        Graph {
            vertices: HashMap::new(),
            edges: Vec::new(),
            inbound_table: HashMap::new(),
            outbound_table: HashMap::new()
        }
    }

    pub fn add_vertex(&mut self, item: T) -> VertexId {
        let id = VertexId::random();
        self.vertices.insert(id.clone(), (item, &id as *const VertexId));
        id
    }

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
                match self.outbound_table.get(&a) {
                    Some(outbounds) => {
                        let mut outbounds = outbounds.clone();
                        outbounds.push(id_ptr2.clone());

                        self.outbound_table.insert(*a, outbounds);
                    },
                    None => {
                        self.outbound_table.insert(*a, vec![id_ptr2.clone()]);
                    }
                }

                // Update inbound table
                match self.inbound_table.get(&b) {
                    Some(inbounds) => {
                        let mut inbounds = inbounds.clone();
                        inbounds.push(id_ptr1.clone());

                        self.inbound_table.insert(*b, inbounds);
                    },
                    None => {
                        self.inbound_table.insert(*b, vec![id_ptr1.clone()]);
                    }
                }

                Ok(())
            },
            _ => Err(GraphErr::NoSuchVertex)
        }
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }
 
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

    #[test]
    fn add_vertices() {
        let mut graph: Graph<usize, ()> = Graph::new();

        let _ = graph.add_vertex(0);
        let _ = graph.add_vertex(1);
        let _ = graph.add_vertex(2);

        assert_eq!(graph.vertex_count(), 3);
    }

    #[test]
    fn add_edges() {
        let mut graph: Graph<usize, ()> = Graph::new();

        let v1 = graph.add_vertex(0);
        let v2 = graph.add_vertex(1);
        let v3 = graph.add_vertex(2);
        let v4 = graph.add_vertex(3);

        graph.add_edge(&v1, &v2);
        graph.add_edge(&v2, &v3);
        graph.add_edge(&v3, &v4);

        assert_eq!(graph.edge_count(), 3);
    }
}