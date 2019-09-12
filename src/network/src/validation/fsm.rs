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

use std::fmt::Debug;

/// An error related to a FSM operation.
pub enum FsmError {
    /// The pushed input is invalid in this state of the FSM.
    BadInput,

    /// The pushed input is potentially valid but the state of 
    /// the FSM is invalid.
    InvalidState,
}

/// Trait describing a general finite-state machine.
pub trait Fsm<I, O> {
    type State: Debug + Clone + PartialEq;

    /// Attempts to push an input into the FSM, performing a transition.
    /// It returns the output if the transition happened.
    fn transition(&mut self, t: I) -> Result<O, FsmError>;

    /// Returns the current state of the FSM.
    fn current_state(&self) -> Self::State;

    /// Returns the final state of the FSM.
    fn default_state(&self) -> Self::State;

    /// Resets the fsm to its initial state.
    fn reset(&mut self);
}