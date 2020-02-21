/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::protocol_flow::block_propagation::*;
use parking_lot::Mutex;
use dashmap::DashMap;
use std::sync::Arc;
use std::default::Default;

/// The pairs buffer size. This number represents
/// the maximum amount of blocks that can be 
/// concurrently propagated at the same time for one
/// peer.
pub const BLOCK_PAIRS_BUFFER_SIZE: usize = 1000;

#[derive(Clone, Debug)]
pub struct BlockPropagation {
    pub(crate) pairs: Arc<DashMap<u64, Pair>>,
}

impl Default for BlockPropagation {
    fn default() -> Self {
        BlockPropagation {
            pairs: Arc::new(DashMap::with_capacity(BLOCK_PAIRS_BUFFER_SIZE)),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Pair {
    pub(crate) sender: Arc<Mutex<BlockSender>>,
    pub(crate) receiver: Arc<Mutex<BlockReceiver>>,
}