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

/// Generic chain interface
pub trait Chain<B> where B: Block {
    /// Returns the current height of the chain
    fn height(&self) -> usize;

    /// Returns an atomic reference to the topmost block in the chain. 
    fn top(&self) -> Arc<B>; 

    /// Attempts to append a new block to the chain.
    fn append_block(&mut self, block: Arc<B>) -> Result<(), ()>; 
}