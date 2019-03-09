// Copyright 2019 Octavian Oncescu

use crate::vertex_id::VertexId;

#[derive(Debug)]
pub struct Vertex<T, M> {
    id: VertexId,
    data: T,
    meta: Option<M>
}