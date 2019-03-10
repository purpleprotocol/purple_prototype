// Copyright 2019 Octavian Oncescu

use crate::vertex_id::VertexId;

#[derive(Debug)]
pub struct Edge<M> {
    inbound: Box<VertexId>,
    outbound: Box<VertexId>,
    weight: f32,
    meta: Option<M>,
}

impl<M> Edge<M> {
    pub fn new(inbound: Box<VertexId>, outbound: Box<VertexId>, meta: Option<M>) -> Edge<M> {
        Edge {
            inbound: inbound,
            outbound: outbound,
            weight: 0.0,
            meta: meta,
        }
    }
}
