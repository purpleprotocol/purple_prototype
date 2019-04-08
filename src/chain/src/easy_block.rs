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

use crate::block::Block;
use chrono::prelude::*;
use crypto::Hash;

#[derive(Debug)]
/// A block belonging to the `EasyChain`.
pub struct EasyBlock {
    /// The hash of the parent block.
    parent_hash: Option<Hash>,

    /// The merkle root hash of the block.
    merkle_root: Option<Hash>,

    /// The hash of the block.
    hash: Option<Hash>,

    /// The timestamp of the block.
    timestamp: DateTime<Utc>,
}

impl Block for EasyBlock {
    fn block_hash(&self) -> Option<Hash> { self.hash.clone() }
    fn parent_hash(&self) -> Option<Hash> { self.parent_hash.clone() }
    fn merkle_root(&self) -> Option<Hash> { self.merkle_root.clone() }
    fn timestamp(&self) -> DateTime<Utc> { self.timestamp.clone() }
}

impl EasyBlock {
    pub fn new(parent_hash: Option<Hash>) -> EasyBlock {
        EasyBlock {
            parent_hash,
            merkle_root: None,
            hash: None,
            timestamp: Utc::now()
        }
    } 

    pub fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<EasyBlock, &'static str> {
        unimplemented!();
    }
}