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
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum OrphanType {
    /// The orphan is a tip block branching
    /// from the canonical chain.
    CanonicalTip,

    /// The orphan is a tip block of a chain that 
    /// is disconnected from the canonical chain.
    PendingTip,

    /// The orphan is first block of a chain that 
    /// is disconnected from the canonical chain.
    PendingHead,

    /// The orphan is both the tip and the first 
    /// block of chain that is disconnected from
    /// the canonical chain.
    PendingTipHead,

    /// The orphan is a block that is branching
    /// from the canonical chain that is not a tip.
    CanonicalNonTip,

    /// The orphan is a block that belongs to a chain
    /// that is disconnected from the canonical chain
    /// and it is neither a tip nor a head.
    PendingNonTip,
}

#[derive(Clone, Debug)]
pub struct OrphanState<B: std::fmt::Debug + Block> {
    orphan: Arc<B>,
    orphan_type: OrphanType
}

impl<B> OrphanState<B> where B: std::fmt::Debug + Block {
    pub fn new(orphan: Arc<B>, orphan_type: OrphanType) -> OrphanState<B> {
        OrphanState {
            orphan,
            orphan_type
        }
    }

    pub fn inner(&self) -> Arc<B> {
        self.orphan.clone()
    }

    pub fn set_type(&mut self, orphan_type: OrphanType) {
        self.orphan_type = orphan_type;
    }

    pub fn orphan_type(&self) -> OrphanType {
        self.orphan_type
    }
}