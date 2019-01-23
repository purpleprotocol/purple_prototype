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

use instruction_set::Instruction;
use stack::Stack;

#[derive(Debug)]
enum Validity {
    Valid,
    Invalid,
    IrrefutablyInvalid
}

#[derive(Debug)]
pub struct Validator {
    state: Validity,
    transitions: Vec<Instruction>,
    stack: Stack<Instruction>
}

impl Validator {
    pub fn new() -> Validator {
        Validator {
            state: Validity::Invalid,
            transitions: Vec::new(),
            stack: Stack::new()
        }
    }

    pub fn switch_state(&mut self, op: Instruction) {
        if let Validity::IrrefutablyInvalid = self.state {
            panic!("Cannot switch state since the state machine is DONE.");
        }

        // If the stack is empty, only accept a block instruction
        if self.stack.len() == 0 {
            match op {
                Instruction::Block => {
                    self.stack.push(op);

                    // TODO: Push transitions
                },
                _ => {
                    // The first instruction can only be a block instruction
                    // so there is nothing more to do at this point.
                    self.state = Validity::IrrefutablyInvalid;
                }
            }
        } else {
            // let valid_states: Vec<&State> = self.transitions
            //     .iter()
            //     .filter(|t| t.possible(op))
            //     .map(|t| &t.next)
            //     .collect();

            // if valid_states.len() == 0 {
            //     Err(())
            // } else {
            //     // Replace self with valid state
            //     *self = *valid_states[0];
            //     Ok(())
            // }
        }
    }

    pub fn done(&self) -> bool {
        match self.state {
            Validity::IrrefutablyInvalid => true,
            _                            => false
        }
    }
    
    pub fn valid(&self) -> bool {
        match self.state {
            Validity::Valid   => true,
            _                 => false
        }
    }
}