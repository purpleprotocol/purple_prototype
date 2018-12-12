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

use stack::Stack;
use frame::Frame;
use value::VmValue;
use code::Code;
use state::State;

pub struct Vm {
    state: State,
    code: Code,
    gas: u64,
    stack: Stack<Frame<VmValue>>
}

pub enum Status {
    Halted,
    Panicked,
    Success
}

impl Vm {
    pub fn new(state: State, code: Code, gas: u64) -> Result<Vm, &'static str> {
        // TODO: Add state and code validations
        Ok(Vm {
            state: state,
            code: code,
            gas: gas,
            stack: Stack::<Frame<VmValue>>::new()
        })
    }

    /// Executes the code loaded in the virtual machine
    /// on the given state.
    ///
    /// If it succeeds, this function returns a 3 element 
    /// tuple: (Status, New state, Gas consumed).
    pub fn execute(&mut self) -> Result<(Status, State, u64), &'static str> {
        unimplemented!();
    }
}