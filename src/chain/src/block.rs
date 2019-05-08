/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

use chrono::prelude::*;
use crypto::Hash;
use std::sync::Arc;
use std::boxed::Box;

/// Generic block interface
pub trait Block {
    /// Returns the genesis block.
    fn genesis() -> Arc<Self>;

    /// Returns the hash of the block.
    fn block_hash(&self) -> Option<Hash>;

    /// Returns the merkle root hash of the block.
    fn merkle_root(&self) -> Option<Hash>;

    /// Returns the parent hash of the block.
    fn parent_hash(&self) -> Option<Hash>;

    /// Returns the timestamp of the block.
    fn timestamp(&self) -> DateTime<Utc>;

    /// Returns the height of the block.
    fn height(&self) -> u64;

    /// Callback that executes after a block is written to a chain.
    fn after_write() -> Option<Box<FnMut(Arc<Self>)>>;

    /// Serializes the block.
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserializes the block
    fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>, &'static str>;
}
