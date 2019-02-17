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
use instruction_set::{Instruction, CT_FLOW_OPS};
use primitives::control_flow::CfOperator;
use code::transition::Transition;

#[derive(Debug)]
enum Validity {
    Valid,
    Invalid,
    IrrefutablyInvalid
}

#[derive(Debug)]
pub struct Validator {
    state: Validity,
    transitions: Vec<Transition>,
    cf_stack: Stack<CfOperator>,
    valid_return: bool
}

impl Validator {
    pub fn new() -> Validator {
        Validator {
            state: Validity::Invalid,
            transitions: Vec::new(),
            valid_return: false,
            cf_stack: Stack::new()
        }
    }

    pub fn push_op(&mut self, op: u8) {
        if let Validity::IrrefutablyInvalid = self.state {
            panic!("Cannot switch state since the state machine is DONE.");
        }

        // If the control flow stack is empty,
        // only accept a begin instruction.
        if self.cf_stack.len() == 0 {
            match Instruction::from_repr(op) {
                Some(Instruction::Begin) => {
                    self.cf_stack.push(CfOperator::Begin);
                    
                    // The next byte after the first begin instruction
                    // is always 0x00, representing a block with 0 arity.
                    self.transitions = vec![Transition::Byte(0x00)];
                },
                _ => {
                    // The first instruction can only be a begin instruction
                    // so there is nothing more to do at this point.
                    self.state = Validity::IrrefutablyInvalid;
                }
            }
        } else {
            let mut next_transitions = None;
            
            {
                let transition = self.transitions
                    .iter()
                    .find(|t| t.accepts_byte(op));

                match transition {
                    Some(Transition::Op(op)) => {
                        let is_ct_flow_op = CT_FLOW_OPS
                            .iter()
                            .find(|o| *o == op);

                        // If op is a control flow op, push it to the stack.
                        match is_ct_flow_op {
                            Some(Instruction::Begin) => self.cf_stack.push(CfOperator::Begin),
                            Some(Instruction::Loop)  => self.cf_stack.push(CfOperator::Loop),
                            Some(Instruction::If)    => self.cf_stack.push(CfOperator::If),
                            Some(Instruction::Else)  => self.cf_stack.push(CfOperator::Else),
                            _                        => { } // Do nothing 
                        }

                        // If op is `End`, pop item from stack.
                        if let Instruction::End = op {
                            // The stack is popped twice in the case 
                            // of terminating an `Else` block.
                            if let &CfOperator::Else = self.cf_stack.peek() {
                                self.cf_stack.pop();
                            }

                            self.cf_stack.pop();
                        }
                        
                        // Changes state to `Valid` if the stack is empty.
                        if self.cf_stack.len() == 0 {
                            self.state = Validity::Valid;
                        } else {
                            let mut next_transitions = op.transitions();
                            let has_loop = self.cf_stack.as_slice()
                                .iter()
                                .any(|o| *o == CfOperator::Loop);

                            // If there is any loop operator in the stack,
                            // allow `Break` and `BreakIf` instructions.
                            if has_loop {
                                next_transitions.push(Transition::Op(Instruction::Break));
                                next_transitions.push(Transition::Op(Instruction::BreakIf));
                            }

                            // Allow `Else` op in case the topmost item
                            // in the stack is an `If` instruction.
                            if let &CfOperator::Else = self.cf_stack.peek() {
                                next_transitions.push(Transition::Op(Instruction::Else));
                            }

                            self.state = Validity::Invalid;
                            next_transitions = Some(next_transitions);
                        }
                    },
                    Some(Transition::Byte(byte)) => {
                        self.state = Validity::Invalid;
                    },
                    Some(Transition::AnyByte) => {
                        self.state = Validity::Invalid;
                    },
                    None => {
                        self.state = Validity::IrrefutablyInvalid;
                    }
                }
            }

            // Set next transitions
            if let Some(next_transitions) = next_transitions {
                self.transitions = next_transitions;
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
use bitvec::Bits;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn it_rejects_code_not_beginning_with_a_block_op() {
        let mut validator = Validator::new();
        validator.push_op(Instruction::Nop.repr());

        assert!(validator.done());
    }

    #[test]
    #[should_panic(expected("done state machine")) ]
    fn it_panics_on_pushing_ops_after_irrefutably_invalid() {
        let mut validator = Validator::new();
    
        validator.push_op(Instruction::Nop.repr());
        validator.push_op(Instruction::Begin.repr());
    }

    #[test]
    fn it_validates_relatively_complex_code() {
        let mut validator = Validator::new();
        let mut bitmask: u8 = 0;
        
        bitmask.set(0, true);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x03,                             // 3 Arity
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i64Const.repr(),
            Instruction::f32Const.repr(),
            0x00,                             // i32 value
            0x00,
            0x00,
            0x05,
            0x00,                             // i64 value
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x1b,
            0x00,                             // f32 value
            0x00,
            0x00,
            0x5f,
            Instruction::PickLocal.repr(),    // Dupe elems on stack 11 times (usize is 16bits)
            0x00,
            0x00,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x00,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PushLocal.repr(),   // Push loop counter to locals stack
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Loop.repr(),
            0x05,                            // 5 arity. The latest 5 items on the caller stack will be pushed to the new frame
            Instruction::PickLocal.repr(),   // Dupe counter
            0x00,
            0x04,
            Instruction::PushOperand.repr(), 
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),    // Push counter to operand stack
            0x00,                            // Loop 5 times
            0x00,
            0x00,
            0x04,
            Instruction::PickLocal.repr(),
            0x00,
            0x00,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::If.repr(),          // Break if items on the operand stack are equal  
            0x02,                            // Arity 0
            Instruction::Eq.repr(),
            Instruction::Break.repr(),       // Break loop
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x02,
            Instruction::Nop.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr(),
            Instruction::PushOperand.repr(), // Increment counter
            0x02,
            bitmask,                         // Reference bits
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::PushLocal.repr(),   // Move counter from operand stack back to call stack
            0x01,
            bitmask,                         // Reference bits
            Instruction::i32Const.repr(),
            Instruction::PopOperand.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        for byte in block {
            validator.push_op(byte);
        }

        assert!(validator.valid());
    }
}