// Copyright 2019 Octavian Oncescu

use std::cell::UnsafeCell;
use std::fmt::Debug;

#[derive(Debug)]
pub struct Edge<T, M> {
    inbound: UnsafeCell<T>,
    outbound: UnsafeCell<T>,
    weight: f32,
    meta: Option<M>
}