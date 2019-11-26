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

use crate::fsm::{BranchFsm, FsmState};
use crate::chain::ChainErr;
use crate::pow_chain::block::PowBlock;
use std::default::Default;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct BValidator {
    state: BranchState,
}

impl BranchFsm<PowBlock> for BValidator {
    type State = BranchState;

    fn mutate_state(&mut self, block: Arc<PowBlock>) -> Result<&Self::State, ChainErr> {
        unimplemented!();
    }

    fn get_state(&self) -> &Self::State {
        &self.state
    }
}

#[cfg(test)]
use crate::chain::tests::DummyBlock;

#[cfg(test)]
impl BranchFsm<DummyBlock> for BValidator {
    type State = BranchState;

    fn mutate_state(&mut self, block: Arc<DummyBlock>) -> Result<&Self::State, ChainErr> {
        unimplemented!();
    }

    fn get_state(&self) -> &Self::State {
        &self.state
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BranchState {
    /// This block allows multiple children
    CanBranch,

    /// This block can be one of the potentially
    /// many parents of a single block.
    CanBeJoined,

    /// The block cannot be branched or joined.
    CannotBeBranchedOrJoined,
}

impl Default for BranchState {
    fn default() -> BranchState {
        BranchState::CanBranch
    }
}

impl FsmState for BranchState {
    fn can_branch(&self) -> bool {
        *self == BranchState::CanBranch
    }

    fn can_be_joined(&self) -> bool {
        *self == BranchState::CanBeJoined
    }
}