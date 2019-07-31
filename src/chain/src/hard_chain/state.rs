/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

use crate::chain::ChainErr;
use crate::easy_chain::chain::EasyChainRef;
use crate::pow_chain_state::PowChainState;
use crate::types::Flushable;
use std::fmt;

#[derive(Clone)]
pub struct HardChainState {
    /// A reference to the associated easy chain.
    easy_chain: EasyChainRef,

    /// The height of the last chosen easy block hash.
    last_easy_height: u64,

    /// Common chain state.
    pow_state: PowChainState,
}

impl fmt::Debug for HardChainState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HardChainState {{ pow_state: {:?}, last_easy_height: {} }}", self.pow_state, self.last_easy_height)
    }
}

impl PartialEq for HardChainState {
    fn eq(&self, other: &Self) -> bool {
        self.pow_state == other.pow_state && self.last_easy_height == other.last_easy_height
    }
}

impl Flushable for HardChainState {
    fn flush(&mut self) -> Result<(), ChainErr> {
        Ok(())
    }
}

impl HardChainState {
    pub fn genesis() -> Self {
        unimplemented!();
    }
}