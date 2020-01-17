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

use crate::types::*;
use crate::{ChainErr, PowBlock};
use chrono::prelude::*;
use crypto::Hash;
use std::boxed::Box;
use std::fmt::Debug;
use std::hash::Hash as HashTrait;
use std::net::SocketAddr;
use std::sync::Arc;

/// Generic block interface
pub trait Block: Debug + PartialEq + Eq + HashTrait + Sized {
    /// Per tip validation state
    type ChainState: Clone + Debug + Flushable + StateInterface;

    /// Size of the block cache.
    const BLOCK_CACHE_SIZE: usize = 20;

    /// Maximum orphans allowed.
    #[cfg(not(test))]
    const MAX_ORPHANS: usize = 100;

    #[cfg(test)]
    const MAX_ORPHANS: usize = 20;

    /// Number of blocks between a valid chain and
    /// the canonical in order for the valid chain
    /// to become canonical
    #[cfg(not(test))]
    const SWITCH_OFFSET: usize = 2;

    #[cfg(test)]
    const SWITCH_OFFSET: usize = 0;

    /// Blocks with height below the canonical height minus
    /// this number will be rejected.
    const MIN_HEIGHT: u64 = 10;

    /// Blocks with height above the canonical height plus
    /// this number will be rejected.
    const MAX_HEIGHT: u64 = 10;

    /// The number of blocks after which a state checkpoint will be made.
    ///
    /// This number **MUST** be less or equal than the minimum accepted height.
    const CHECKPOINT_INTERVAL: usize = 5;

    /// Max checkpoints to keep. This number must be less or equal
    /// than `(MAX_HEIGHT + MIN_HEIGHT) / CHECKPOINT_INTERVAL`.
    const MAX_CHECKPOINTS: usize = 4;

    /// How many blocks to keep behind the canonical
    /// chain tip when pruning is enabled. This number should
    /// be equal to `CHECKPOINT_INTERVAL * MAX_CHECKPOINTS`.
    const BLOCKS_TO_KEEP: usize = 100;

    /// Returns the genesis block.
    fn genesis() -> Arc<Self>;

    /// Returns true if the block is the genesis block.
    fn is_genesis(&self) -> bool;

    /// Returns the genesis state of the chain
    fn genesis_state() -> Self::ChainState;

    /// Returns the hash of the block.
    fn block_hash(&self) -> Option<Hash>;

    /// Returns the parent hash of the block.
    fn parent_hash(&self) -> Hash;

    /// Returns the timestamp of the block.
    fn timestamp(&self) -> DateTime<Utc>;

    /// Returns the height of the block.
    fn height(&self) -> u64;

    /// Callback that executes after a block is written to a chain.
    fn after_write() -> Option<Box<dyn FnMut(Arc<Self>)>>;

    /// Condition that must result if successful, returns the state
    /// that is to be associated with the new appended block.
    ///
    /// If this functions returns an `Err`, the block will not be appended.
    fn append_condition(
        block: Arc<Self>,
        chain_state: Self::ChainState,
        branch_type: BranchType,
    ) -> Result<Self::ChainState, ChainErr>;

    /// Serializes the block.
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserializes the block
    fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>, &'static str>;
}