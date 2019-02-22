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
use primitives::r#type::VmType;
use code::transition::Transition;
use bitvec::Bits;

#[derive(Debug)]
enum Validity {
    Valid,
    Invalid,
    IrrefutablyInvalid
}

#[derive(Debug)]
pub struct Validator {
    /// The state of the validator
    state: Validity,

    /// Valid transitions 
    transitions: Vec<Transition>,

    /// Stack used for validating operand arguments
    validation_stack: Stack<(u8, bool)>,
    
    /// Buffer used to store pre-validated values
    validation_buffer: Vec<u8>,

    /// Stack that holds the control flow structure
    cf_stack: Stack<CfOperator>
}

impl Validator {
    pub fn new() -> Validator {
        Validator {
            state: Validity::Invalid,
            transitions: Vec::new(),
            cf_stack: Stack::new(),
            validation_stack: Stack::new(),
            validation_buffer: Vec::new()
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
                    // Push `Begin` operator to control flow stack.
                    self.cf_stack.push(CfOperator::Begin);

                    // The first element in the validation stack 
                    // is the operand that is being validated.
                    self.validation_stack.push((Instruction::Begin.repr(), true));
                    
                    // The next byte after the first begin instruction
                    // is always 0x00, representing 0 arity.
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
            let mut t = None;
            
            {
                let transition = self.transitions
                    .iter()
                    .find(|t| t.accepts_byte(op));

                if let Some(transition) = transition {
                    t = Some(transition.clone());
                } 
            }

            let transition = t;

            match transition {
                Some(Transition::Op(op)) => {
                    let is_ct_flow_op = CT_FLOW_OPS
                        .iter()
                        .find(|o| *o == &op);

                    // If op is a control flow op, push it to the cf stack.
                    match is_ct_flow_op {
                        Some(Instruction::Begin) => self.cf_stack.push(CfOperator::Begin),
                        Some(Instruction::Loop)  => self.cf_stack.push(CfOperator::Loop),
                        Some(Instruction::If)    => self.cf_stack.push(CfOperator::If),
                        Some(Instruction::Else)  => self.cf_stack.push(CfOperator::Else),
                        _                        => { } // Do nothing 
                    }

                    let mut allow_else = false;

                    // If op is `End`, pop item from stack.
                    if let Instruction::End = op {
                        if let &CfOperator::If = self.cf_stack.peek() {
                            allow_else = true;
                        }

                        self.cf_stack.pop();
                    }
                    
                    // Changes state to `Valid` if the stack is empty.
                    if self.cf_stack.len() == 0 {
                        self.state = Validity::Valid;
                    } else {
                        let mut next = match op {
                            // TODO: Return transitions for all ops with non-default transitions
                            Instruction::PushLocal => {
                                // Mark op for argument validation
                                self.validation_stack.push((Instruction::PushLocal.repr(), true));
                                
                                ARITY_TRANSITIONS.to_vec()
                            },
                            Instruction::PushOperand => {
                                // Mark op for argument validation
                                self.validation_stack.push((Instruction::PushOperand.repr(), true));
                                
                                ARITY_TRANSITIONS.to_vec()
                            },
                            Instruction::PickLocal => {
                                // Mark op for argument validation
                                self.validation_stack.push((Instruction::PickLocal.repr(), true));

                                vec![Transition::AnyByte]
                            },
                            Instruction::Loop => {
                                // Mark op for argument validation
                                self.validation_stack.push((Instruction::Loop.repr(), true));
                                
                                ARITY_TRANSITIONS.to_vec()
                            },
                            Instruction::If => {
                                // Mark op for argument validation
                                self.validation_stack.push((Instruction::If.repr(), true));
                                
                                ARITY_TRANSITIONS.to_vec()
                            },
                            Instruction::Else => {
                                // Mark op for argument validation
                                self.validation_stack.push((Instruction::Else.repr(), true));
                                
                                ARITY_TRANSITIONS.to_vec()
                            },
                            _ => op.transitions()
                        };

                        let has_loop = self.cf_stack
                            .as_slice()
                            .iter()
                            .any(|o| *o == CfOperator::Loop);

                        // If there is any loop operator in the stack,
                        // allow `Break` and `BreakIf` instructions.
                        if has_loop {
                            next.push(Transition::Op(Instruction::Break));
                            next.push(Transition::Op(Instruction::BreakIf));
                        }

                        // Allow `Else` op in case the topmost item
                        // in the stack was an `If` instruction.
                        if allow_else {
                            next.push(Transition::Op(Instruction::Else));
                        }

                        self.state = Validity::Invalid;
                        next_transitions = Some(next);
                    }
                },
                Some(Transition::Byte(_)) | Some(Transition::AnyByte) => {
                    let (operand, _) = self.validation_stack.as_slice()[0];

                    match Instruction::from_repr(operand) {
                        Some(Instruction::Begin) => {
                            if self.validation_stack.len() != 1 {
                                panic!(format!("The validation stack can only have 1 element at this point! Got: {}", self.validation_stack.len()));
                            }

                            let byte = if let Some(Transition::Byte(byte)) = transition {
                                byte
                            } else {
                                panic!("Invalid transition! Expected a byte transition!");
                            };

                            self.validation_stack.pop();

                            // Only allow 0 arity for first begin block
                            if self.cf_stack.len() == 1 && byte == 0x00 {
                                self.state = Validity::Invalid;
                                next_transitions = Some(Instruction::Begin.transitions());
                            } else if self.cf_stack.len() == 1 {
                                // The arity is not 0 so anything further 
                                // is invalid as well.
                                self.state = Validity::IrrefutablyInvalid;
                            } else {
                                let valid = ARITY_TRANSITIONS
                                    .iter()
                                    .any(|t| t.accepts_byte(op));

                                if valid {
                                    self.state = Validity::Invalid;
                                    next_transitions = Some(Instruction::Begin.transitions());
                                } else {
                                    self.state = Validity::IrrefutablyInvalid;
                                }
                            }
                        },
                        Some(Instruction::Loop) => {
                            if self.validation_stack.len() != 1 {
                                panic!(format!("The validation stack can only have 1 element at this point! Got: {}", self.validation_stack.len()));
                            }

                            self.validation_stack.pop();

                            let valid = ARITY_TRANSITIONS
                                .iter()
                                .any(|t| t.accepts_byte(op));

                            if valid {
                                self.state = Validity::Invalid;
                                next_transitions = Some(Instruction::Loop.transitions());
                            } else {
                                self.state = Validity::IrrefutablyInvalid;
                            }
                        },
                        Some(Instruction::PushOperand) => {
                            self.validate_push(op, &transition, &mut next_transitions);
                        },
                        Some(Instruction::PushLocal) => {
                            self.validate_push(op, &transition, &mut next_transitions);
                        },
                        Some(Instruction::PickLocal) => {
                            self.validation_buffer.push(op);

                            if self.validation_buffer.len() == 2 {
                                match decode_be_u16!(&self.validation_buffer) {
                                    Ok(_) => {
                                        // Cleanup
                                        self.validation_buffer = vec![];
                                        self.validation_stack = Stack::new();

                                        next_transitions = Some(Instruction::Begin.transitions());
                                        self.state = Validity::Invalid;
                                    },
                                    Err(_) => {
                                        self.state = Validity::IrrefutablyInvalid;
                                    }
                                }
                            } 
                        },
                        Some(Instruction::If) => {
                            if self.validation_stack.len() != 1 {
                                panic!(format!("The validation stack can only have 1 element at this point! Got: {}", self.validation_stack.len()));
                            }

                            self.validation_stack.pop();

                            let valid = ARITY_TRANSITIONS
                                .iter()
                                .any(|t| t.accepts_byte(op));

                            if valid {
                                self.state = Validity::Invalid;
                                next_transitions = Some(Instruction::If.transitions());
                            } else {
                                self.state = Validity::IrrefutablyInvalid;
                            }
                        },
                        Some(Instruction::Else) => {
                            if self.validation_stack.len() != 1 {
                                panic!(format!("The validation stack can only have 1 element at this point! Got: {}", self.validation_stack.len()));
                            }

                            self.validation_stack.pop();

                            let valid = ARITY_TRANSITIONS
                                .iter()
                                .any(|t| t.accepts_byte(op));

                            if valid {
                                self.state = Validity::Invalid;
                                next_transitions = Some(Instruction::Else.transitions());
                            } else {
                                self.state = Validity::IrrefutablyInvalid;
                            }
                        },
                        _ => unimplemented!()
                    }
                },
                None => {
                    self.state = Validity::IrrefutablyInvalid;
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
            Validity::Valid   => true,
            _                 => false
        }
    }

    fn validate_push(&mut self, op: u8, transition: &Option<Transition>, next_transitions: &mut Option<Vec<Transition>>) {
        // Based on the length of the validation stack,
        // we perform different validations.
        match self.validation_stack.len() {
            // Validate arity
            1 => { 
                let arity = if let Some(Transition::Byte(byte)) = transition {
                    byte
                } else {
                    panic!("Invalid transition! Expected a byte transition!");
                };

                // Push arity to validation stack
                self.validation_stack.push((*arity, true));

                // Continue validating
                self.state = Validity::Invalid;

                // Next byte will be the bitmask so we allow any
                *next_transitions = Some(vec![Transition::AnyByte]);
            },

            // Validate bitmask
            2 => {
                let bitmask = op;

                // Push bitmask to validation stack
                self.validation_stack.push((bitmask, true));

                // Continue validating
                self.state = Validity::Invalid;

                // The next transitions are the argument types
                *next_transitions = Some(ARG_DECLARATIONS.to_vec());
            },

            len => {
                let (arity, _) = self.validation_stack.as_slice()[1];

                // This is the intended length of the validation stack
                let offset = (arity + 2) as usize;
                
                if len >= 3 && len <= offset {                  // Validate argument types
                    self.validation_stack.push((op, false));

                    if len == offset {
                        // All arg types are pushed to the validation stack
                        // so we now allow any byte for validating the values
                        // themselves.
                        *next_transitions = Some(vec![Transition::AnyByte]);
                    } else {
                        // The next transitions are still the argument types
                        *next_transitions = Some(ARG_DECLARATIONS.to_vec());
                    }

                    // Continue validating
                    self.state = Validity::Invalid;
                } else if len > offset {      // Validate arguments
                    let (arg_type, elem_idx) = get_next_elem(&self.validation_stack);
                    
                    // Push op to validation buffer
                    self.validation_buffer.push(op);

                    // Individual bytes that compose the validated
                    // value are pushed into the validation buffer.
                    //
                    // Once the validation buffer matches the length
                    // of the validated type, we actually perform 
                    // the validation.
                    if self.validation_buffer.len() == arg_type.byte_size() {
                        if arg_type.validate_structure(&self.validation_buffer) {
                            if elem_idx == offset {
                                // Cleanup in case this is the last validated argument
                                self.validation_stack = Stack::new();
                                *next_transitions = Some(Instruction::Begin.transitions());
                            } else {
                                let val_stack = self.validation_stack.as_mut_slice();
                                let (arg, _) = val_stack[elem_idx];

                                // Mark as done
                                val_stack[elem_idx] = (arg, true);
                            }

                            // Cleanup
                            self.validation_buffer = vec![];
                            
                            // Continue validating
                            self.state = Validity::Invalid;
                        } else {
                            // Stop validating
                            self.state = Validity::IrrefutablyInvalid;

                            // Cleanup
                            self.validation_buffer = vec![];
                            self.validation_stack = Stack::new();
                        };
                    }
                } else {
                    panic!(format!("The validation stack cannot have {} operands!", len));
                }
            }
        }
    }
}

fn get_next_elem(val_stack: &Stack<(u8, bool)>) -> (VmType, usize) {
    let val_stack = val_stack.as_slice();
    let mut vm_type = None;
    let mut idx = 0;

    for (byte, validated) in val_stack.iter() {
        if !validated {
            let ret_type = VmType::from_op(*byte).unwrap();

            vm_type = Some(ret_type);
            break;
        }

        idx += 1;
    }

    (vm_type.unwrap(), idx)
}

lazy_static! {
    static ref ARITY_TRANSITIONS: Vec<Transition> = (0..9)
        .into_iter()
        .map(|x| Transition::Byte(x))
        .collect();

    static ref ARG_DECLARATIONS: Vec<Transition> = vec![
        Transition::Byte(Instruction::i32Const.repr()),
        Transition::Byte(Instruction::i64Const.repr()),
        Transition::Byte(Instruction::f32Const.repr()),
        Transition::Byte(Instruction::f64Const.repr())
    ];
}

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
    #[should_panic(expected("done state machine"))]
    fn it_panics_on_pushing_ops_after_irrefutably_invalid() {
        let mut validator = Validator::new();
    
        validator.push_op(Instruction::Nop.repr());
        validator.push_op(Instruction::Begin.repr());
    }

    #[test]
    #[should_panic(expected("done state machine"))]
    fn it_fails_with_invalid_first_begin_arity() {
        let mut validator = Validator::new();
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x01,                             
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        for byte in block {
            validator.push_op(byte);
        }
    }

    #[test]
    #[should_panic(expected("done state machine"))]
    fn it_fails_with_invalid_nested_begin_arity() {
        let mut validator = Validator::new();
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             
            Instruction::Nop.repr(),
            Instruction::Begin.repr(),
            0x09,
            Instruction::Nop.repr(),
            Instruction::End.repr(),
            Instruction::End.repr()
        ];

        for byte in block {
            validator.push_op(byte);
        }
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
            println!("DEBUG {:x?}, {:?}", byte, Instruction::from_repr(byte));
            validator.push_op(byte);
        }

        assert!(validator.valid());
    }

    #[test]
    fn it_fails_with_invalid_bitmask1() {
        let mut validator = Validator::new();
        let mut bitmask: u8 = 0;
        
        bitmask.set(1, true);

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

            if validator.done() {
                break;
            }
        }

        assert!(!validator.valid());
    }

    #[test]
    fn it_fails_with_invalid_bitmask2() {
        let mut validator = Validator::new();
        let mut bitmask: u8 = 0;
        
        bitmask.set(1, true);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x03,                             // 3 Arity
            bitmask,
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

            if validator.done() {
                break;
            }
        }

        assert!(!validator.valid());
    }
}