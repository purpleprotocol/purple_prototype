// Copyright 2019 Octavian Oncescu

use crate::vertex_id::VertexId;
use std::sync::Arc;

#[derive(Debug)]
pub struct Edge<M> {
    inbound: Arc<VertexId>,
    outbound: Arc<VertexId>,
    weight: f32,
    meta: Option<M>,
}

impl<M> Edge<M> {
    pub fn new(inbound: Arc<VertexId>, outbound: Arc<VertexId>, meta: Option<M>) -> Edge<M> {
        Edge {
            inbound: inbound,
            outbound: outbound,
            weight: 0.0,
            meta: meta,
        }
    }

    /// Returns true if either the inbound or outbound
    /// vertex is matching the given `VertexId`.
    pub fn matches_any(&self, id: &VertexId) -> bool {
        id == self.inbound.as_ref() || id == self.outbound.as_ref()
    }
}