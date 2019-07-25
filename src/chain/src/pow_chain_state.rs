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

use crate::chain::ChainErr;
use crate::types::*;

#[derive(Clone, Debug)]
/// Chain state associated with proof-of-work chains.
/// This is used to calculate the difficulty on the 
/// `EasyChain` and on the `HardChain`.
pub struct PowChainState {
    /// The current chain height
    height: u64,

    /// Current difficulty
    difficulty: u64,
}

impl PowChainState {
    pub fn genesis() -> Self {
        PowChainState { height: 0, difficulty: 0 }
    }
}

impl Flushable for PowChainState {
    fn flush(&mut self) -> Result<(), ChainErr> {
        Ok(())
    }
}