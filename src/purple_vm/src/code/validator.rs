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

use instruction_set::{Instruction, OPS_LIST, CT_FLOW_OPS};
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
    stack: Stack<Instruction>,
    valid_return: bool
}

impl Validator {
    pub fn new() -> Validator {
        Validator {
            state: Validity::Invalid,
            transitions: Vec::new(),
            valid_return: false,
            stack: Stack::new()
        }
    }

    pub fn push_op(&mut self, op: Instruction) {
        if let Validity::IrrefutablyInvalid = self.state {
            panic!("Cannot switch state since the state machine is DONE.");
        }

        // If the stack is empty, only accept a begin instruction
        if self.stack.len() == 0 {
            match op {
                Instruction::Begin => {
                    self.stack.push(op);
                    
                    // All ops are allowed after the first begin instruction
                    self.transitions = OPS_LIST.to_vec();
                },
                _ => {
                    // The first instruction can only be a begin instruction
                    // so there is nothing more to do at this point.
                    self.state = Validity::IrrefutablyInvalid;
                }
            }
        } else {
            let valid_transition = self.transitions
                .iter()
                .any(|t| *t == op);

            if valid_transition {
                let is_ct_flow_op = CT_FLOW_OPS
                    .iter()
                    .any(|o| *o == op);

                // If op is a control flow op, push it to the stack.
                if is_ct_flow_op {
                    self.stack.push(op);
                }

                // If op is `End`, pop item from stack.
                if let Instruction::End = op {
                    // The stack is popped twice in the case 
                    // of terminating an `Else` block.
                    if let &Instruction::Else = self.stack.peek() {
                        self.stack.pop();
                    }

                    self.stack.pop();
                }
                
                // Changes state to `Valid` if the stack is empty.
                if self.stack.len() == 0 {
                    self.state = Validity::Valid;
                } else {
                    let mut next_ops = op.transitions();
                    let has_loop = self.stack.as_slice()
                        .iter()
                        .any(|o| *o == Instruction::Loop);

                    // If there is any loop operator in the stack,
                    // allow `Break` and `BreakIf` instructions.
                    if has_loop {
                        next_ops.push(Instruction::Break);
                        next_ops.push(Instruction::BreakIf);
                    }

                    // Allow `Else` op in case the topmost item
                    // in the stack is an `If` instruction.
                    if let &Instruction::If = self.stack.peek() {
                        next_ops.push(Instruction::Else);
                    }

                    self.state = Validity::Invalid;
                    self.transitions = next_ops;
                }
            } else {
                self.state = Validity::IrrefutablyInvalid;
            }
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
            Validity::Valid   => self.valid_return,
            _                 => false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn it_rejects_code_not_beginning_with_a_block_op() {
        let mut validator = Validator::new();
        validator.push_op(Instruction::Nop);

        assert!(validator.done());
    }

    #[test]
    #[should_panic(expected("done state machine")) ]
    fn it_panics_on_pushing_ops_after_irrefutably_invalid() {
        let mut validator = Validator::new();
    
        validator.push_op(Instruction::Nop);
        validator.push_op(Instruction::Begin);
    }
}