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

use crate::instruction_set::{Instruction, CT_FLOW_OPS};
use crate::primitives::r#type::VmType;
use crate::stack::Stack;
use bitvec::Bits;

#[derive(Clone, Debug)]
pub struct Function {
    /// The number of arguments that the function receives.
    pub arity: u8,

    /// The block of code associated with the function.
    pub block: Vec<u8>,

    /// The name of the function.
    pub name: String,

    /// The types of the arguments.
    pub arguments: Vec<VmType>,

    // The return type of the function.
    pub return_type: Option<VmType>,
}

impl Function {
    pub fn fetch(&self, idx: usize) -> u8 {
        if idx >= self.block.len() {
            panic!("Invalid index!");
        } else {
            self.block[idx]
        }
    }

    pub fn fetch_block_len(&self, idx: usize) -> usize {
        let op = self.block[idx];

        match Instruction::from_repr(op) {
            Some(Instruction::Begin) => self.find_block_len(idx),
            Some(Instruction::Loop) => self.find_block_len(idx),
            Some(Instruction::If) => self.find_block_len(idx),
            Some(Instruction::Else) => self.find_block_len(idx),
            _ => {
                panic!("The length of a block can only be queried for a control flow instruction!")
            }
        }
    }

    // TODO: Cache this
    fn find_block_len(&self, idx: usize) -> usize {
        let mut result_len: usize = 0;
        let mut offset: usize = 0;
        let mut stack: Stack<()> = Stack::new();
        let len = self.block.len();

        for i in idx..len {
            result_len += 1;

            if let Some(op) = Instruction::from_repr(self.block[i + offset]) {
                let is_cf_operator = CT_FLOW_OPS.iter().any(|o| *o == op);

                if let Instruction::End = op {
                    stack.pop();

                    if stack.len() == 0 {
                        break;
                    }
                } else if is_cf_operator {
                    // Escape arity
                    if let Instruction::If = op {
                        // In case of `If` instruction, we escape
                        // 2 characters, in order to include the
                        // comparison operator as well.
                        offset += 2;
                        result_len += 2;
                    } else {
                        offset += 1;
                        result_len += 1;
                    }

                    stack.push(());
                } else {
                    // TODO: Account offset and length for any instruction that receives args
                    match op {
                        Instruction::PickLocal => {
                            // Account for idx
                            offset += 2;
                            result_len += 2;
                        }
                        Instruction::Call => {
                            offset += 2;
                            result_len += 2;
                        }
                        Instruction::Return => {
                            offset += 1;
                            result_len += 1;
                        }
                        Instruction::PushLocal => {
                            let mut acc = 0;

                            offset += 1;
                            result_len += 1;

                            let arity = self.block[i + offset];

                            offset += 1;
                            result_len += 1;

                            let bitmask = self.block[i + offset];

                            for j in 0..arity {
                                offset += 1;
                                result_len += 1;

                                let arg_primitive_type = self.block[i + offset];

                                match VmType::from_op(arg_primitive_type) {
                                    Some(op) => match bitmask.get(j) {
                                        false => {
                                            let byte_size = op.byte_size();

                                            // Increment both len and offset with
                                            // the byte size of the type
                                            result_len += byte_size;
                                            acc += byte_size;
                                        }
                                        true => {
                                            // Pop operand, so we increment only by 1
                                            result_len += 1;
                                            acc += 1;
                                        }
                                    },
                                    None => panic!("Invalid type!"),
                                };
                            }

                            offset += acc;
                        }
                        Instruction::PushOperand => {
                            let mut acc = 0;

                            offset += 1;
                            result_len += 1;

                            let arity = self.block[i + offset];

                            offset += 1;
                            result_len += 1;

                            let bitmask = self.block[i + offset];

                            for j in 0..arity {
                                offset += 1;
                                result_len += 1;

                                let arg_primitive_type = self.block[i + offset];

                                match VmType::from_op(arg_primitive_type) {
                                    Some(op) => match bitmask.get(j) {
                                        false => {
                                            let byte_size = op.byte_size();

                                            // Increment both len and offset with
                                            // the byte size of the type
                                            result_len += byte_size;
                                            acc += byte_size;
                                        }
                                        true => {
                                            // Pop operand, so we increment only by 1
                                            result_len += 1;
                                            acc += 1;
                                        }
                                    },
                                    None => panic!("Invalid type!"),
                                };
                            }

                            offset += acc;
                        }
                        _ => {
                            // Do nothing
                        }
                    }
                }
            }
        }

        result_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn find_block_len() {
        let mut bitmask: u8 = 0;

        bitmask.set(0, true);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x03,                             // 3 Arity
            0x00,                             // Reference bits
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
            0x00,                            // Reference bits
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

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: Some(VmType::I32),
            arguments: vec![]
        }; 
        
        assert_eq!(function.find_block_len(72), 5);
    }

    #[test]
    #[rustfmt::skip]
    fn find_block_len_with_nested1() {
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
            0x00,                            // Reference bits
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
            bitmask,                         // Reference bits
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

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: Some(VmType::I32),
            arguments: vec![]
        }; 

        assert_eq!(function.find_block_len(0), function.block.len());
    }

    #[test]
    #[rustfmt::skip]
    fn find_block_len_with_nested2() {
        let mut bitmask: u8 = 0;

        bitmask.set(0, true);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x03,                             // 3 Arity
            0x00,                             // Reference bits
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
            bitmask,
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
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::PopOperand.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: Some(VmType::I32),
            arguments: vec![]
        }; 

        assert_eq!(function.find_block_len(51), 48);
    }

    #[test]
    #[rustfmt::skip]
    fn find_block_len_with_call_and_return() {
        let mut bitmask: u8 = 0;

        bitmask.set(0, true);

        let main_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Loop.repr(),
            0x01,
            Instruction::Call.repr(),
            0x00,                             // Fun idx (16 bits)
            0x04,          
            Instruction::PickLocal.repr(),
            0x00,
            0x00,           
            Instruction::PushOperand.repr(),
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            0x00,                             // Loop 4 times
            0x00,
            0x00,
            0x04,
            Instruction::BreakIf.repr(),
            Instruction::Eq.repr(),
            Instruction::End.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test1".to_owned(),
            block: main_block,
            return_type: None,
            arguments: vec![]
        };

        assert_eq!(function.find_block_len(11), 21);
    }
}
