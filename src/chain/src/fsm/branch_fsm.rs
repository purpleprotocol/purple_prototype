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
use crate::block::Block;
use std::fmt::Debug;
use std::sync::Arc;

/// General trait for describing a finite-state machine
/// used for chain branch validations.
pub trait BranchFsm<B: Block>: Clone + Debug + Default {
    type State: FsmState;

    /// Attempts to mutate the state of the finite-state machine,
    /// returning a reference to the new state if successful.
    fn mutate_state(&mut self, block: Arc<B>) -> Result<&Self::State, ChainErr>;

    /// Retrieves a reference to the current state of the finite-state-machine
    fn get_state(&self) -> &Self::State;
}

/// General trait for describing the state of a finite-state
/// machine used for chain branch validations.
pub trait FsmState: Clone + Debug + PartialEq + Default {
    /// Returns `true` if the current block can have multiple
    /// children who branch off. It is a logic error for multiple
    /// method implementations to return `true` on the state.
    fn can_branch(&self) -> bool;

    /// Returns `true` if the current branch can be joined along
    /// with other finished branches into a single, unified chain.
    fn can_be_joined(&self) -> bool;
}