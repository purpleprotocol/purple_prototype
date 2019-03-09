use std::sync::Arc;

#[derive(Debug)]
pub struct Graph<T, M> {
    vertices: Vec<Arc<Vertex<T>>,
    edges: Vec<Arc<Edge<T, M>>,
    inbound_table: HashMap<VertexId, Arc<Edge<T, M>>>,
    outbound_table: HashMap<VertexId, Arc<Edge<T, M>>> 
}