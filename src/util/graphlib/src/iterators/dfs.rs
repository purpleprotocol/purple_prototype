// Copyright 2019 Octavian Oncescu

use crate::vertex_id::VertexId;
use crate::graph::Graph;

use std::sync::Arc;

#[derive(Debug)]
pub struct Dfs<'a, T, M> {
    recursion_stack: Vec<Arc<VertexId>>,
    visited_stack: Vec<Arc<VertexId>>,
    roots_stack: Vec<Arc<VertexId>>,
    iterable: &'a Graph<T, M>
}

impl<'a, T, M> Dfs<'a, T, M> {
    pub fn new(graph: &'a Graph<T, M>) -> Dfs<'_, T, M> {
        let mut roots_stack = Vec::with_capacity(graph.roots_count());

        for v in graph.roots() {
            roots_stack.push(Arc::from(*v));
        }

        Dfs {
            visited_stack: Vec::with_capacity(graph.vertex_count()),
            recursion_stack: Vec::with_capacity(graph.vertex_count()),
            roots_stack: roots_stack,
            iterable: graph
        }
    }
}

impl<'a, T, M> Iterator for Dfs<'a, T, M> {
    type Item = &'a VertexId;

    fn next(&mut self) -> Option<Self::Item> {
        while self.roots_stack.len() != 0 {
            let root = self.roots_stack[self.roots_stack.len()-1].clone();

            // No vertices have been visited yet,
            // so we begin from the current root.
            if self.visited_stack.is_empty() {
                self.visited_stack.push(root.clone());
                self.recursion_stack.push(root.clone());
                
                return self.iterable.fetch_id_ref(root.as_ref());
            } 

            // Check if the topmost item on the recursion stack
            // has inbound neighbors. If it does, we traverse
            // them until we find one that is unvisited.
            //
            // If either the topmost item on the recursion stack
            // doesn't have neighbors or all of its neighbors
            // are visited, we pop it from the stack.
            let mut current = self.recursion_stack.pop().unwrap();

            loop {
                if self.iterable.in_neighbors_count(current.as_ref()) == 0 && self.recursion_stack.len() > 0 {
                    current = self.recursion_stack.pop().unwrap();
                    continue;
                } 

                break;
            }

            // Traverse current neighbors
            for n in self.iterable.out_neighbors(current.as_ref()) {
                if !self.visited_stack.iter().any(|x| **x == *n) {
                    self.visited_stack.push(Arc::from(*n));
                    self.recursion_stack.push(current);
                    self.recursion_stack.push(Arc::from(*n));

                    return Some(n);
                }
            }

            // Begin traversing from next root if the
            // recursion stack is empty.
            if self.recursion_stack.is_empty() {
                self.visited_stack = Vec::with_capacity(self.iterable.vertex_count());
                self.roots_stack.pop();
            }
        } 

        None
    }
}