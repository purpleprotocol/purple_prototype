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

use crate::types::*;
use crate::chain::ChainErr;
use persistence::PersistentDb;
use consensus::PoolState;

/// Wrapper over the `StateChain` associated chain state.
#[derive(Clone, Debug)]
pub struct ChainState {
    /// Database storing the ledger ephemeral state.
    pub(crate) db: PersistentDb,

    /// The un-flushed validator pool state
    pub(crate) pool_state: PoolState,
}

impl ChainState {
    const POOL_STATE_KEY: &'static [u8] = b"pool_state";
    
    pub fn new(db: PersistentDb) -> ChainState {
        ChainState {
            db,
            pool_state: PoolState::new(0, 1000) // TODO: Retrieve/calculate pool state from database
        }
    }
}

impl Flushable for ChainState {
    fn flush(&mut self) -> Result<(), ChainErr> {
        unimplemented!();
    }
}