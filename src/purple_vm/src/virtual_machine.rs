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
use primitives::value::VmValue;
use primitives::r#type::VmType;
use primitives::control_flow::CfOperator;
use code::function::Function;
use address::Address;
use module::Module;
use instruction_set::{Instruction, COMP_OPS};
use patricia_trie::{TrieMut, TrieDBMut};
use persistence::{BlakeDbHasher, Codec};
use byteorder::{BigEndian, ReadBytesExt};
use error::VmError;
use std::io::Cursor;

// TODO: Determine a better value for this
const MAX_OP_ARITY: u8 = 50;

#[derive(Debug)]
pub struct Vm {
    ip: Option<Address>,
    modules: Vec<Module>,
    call_stack: Stack<Frame<VmValue>>,
    operand_stack: Stack<VmValue>
}

impl Vm {
    pub fn new() -> Vm {
        Vm {
            modules: Vec::new(),
            ip: None,
            call_stack: Stack::<Frame<VmValue>>::new(),
            operand_stack: Stack::<VmValue>::new()
        }
    }

    /// Loads a module into the virtual machine
    pub fn load(&mut self, module: Module) -> Result<(), VmError> {
        if self.modules.iter().any(|m| m == &module) {
            Err(VmError::AlreadyLoaded)
        } else {
            self.modules.push(module);
            Ok(())
        }
    }


    /// Unloads the module at the given index, if any.
    pub fn unload(&mut self, idx: usize) {
        if idx < self.modules.len() {
            self.modules.remove(idx);
        }
    }

    /// Executes the code loaded in the virtual machine
    /// on the given state.
    ///
    /// If it succeeds, this function returns the amount
    /// of gas that was consumed.
    pub fn execute(
        &mut self, 
        trie: &mut TrieDBMut<BlakeDbHasher, Codec>, 
        module_idx: usize, 
        fun_idx: usize,
        argv: &[VmValue], 
        gas: u64
    ) -> Result<u64, VmError> {
        // Check module definition
        if module_idx >= self.modules.len() {
            return Err(VmError::NotLoaded);
        }

        let module = &self.modules[module_idx];

        // Check function definition
        if fun_idx >= module.functions.len() {
            return Err(VmError::NotDefined);
        }

        // Create instruction pointer
        let ip = Address::new(0, fun_idx, module_idx);

        // Set instruction pointer
        self.ip = Some(ip);

        // Execute code
        loop {
            if let Some(ref mut ip) = self.ip {
                let module = &self.modules[ip.module_idx];
                let fun = &module.functions[ip.fun_idx];
                let op = fun.fetch(ip.ip);

                if let Some(op) = Instruction::from_repr(op) {
                    println!("DEBUG OP: {:?}", op);
                }

                println!("DEBUG IP: {}", ip.ip);

                match Instruction::from_repr(op) {
                    Some(Instruction::Halt) => {
                        break;
                    },
                    Some(Instruction::Nop) => {
                        // This does nothing. Just increment the instruction pointer.
                        ip.increment();
                    },
                    Some(Instruction::Begin) => {
                        handle_begin_block(CfOperator::Begin, ip, &mut self.call_stack, &fun, &argv);
                    },
                    Some(Instruction::Loop) => {
                        handle_begin_block(CfOperator::Loop, ip, &mut self.call_stack, &fun, &argv);
                    },
                    Some(Instruction::PushOperand) => {
                        // TODO: Dissalow pushing operands of multiple types

                        ip.increment();

                        // The next byte after a `PushOperand` instruction
                        // is always the arity of the instruction.
                        let arity = fun.fetch(ip.ip);

                        if arity > MAX_OP_ARITY {
                            panic!(format!("Arity cannot be greater than {}!", MAX_OP_ARITY));
                        }

                        if arity == 0 {
                            panic!("The arity of a PushOperand instruction cannot be 0");
                        }

                        // Fetch arguments
                        let frame = self.call_stack.peek_mut();
                        let (_, argv) = fetch_argv(frame, &mut self.operand_stack, ip, fun, arity as usize);

                        // Push arguments to operand stack
                        for arg in argv {
                            self.operand_stack.push(arg);
                        }

                        ip.increment();
                    },
                    Some(Instruction::PushLocal) => {
                        ip.increment();

                        // The next byte after a `PushLocal` instruction
                        // is always the arity of the instruction.
                        let arity = fun.fetch(ip.ip);

                        if arity > MAX_OP_ARITY {
                            panic!(format!("Arity cannot be greater than {}!", MAX_OP_ARITY));
                        }

                        if arity == 0 {
                            panic!("The arity of a PushLocal instruction cannot be 0");
                        }

                        // Fetch arguments
                        let (_, argv) = fetch_argv(self.call_stack.peek_mut(), &mut self.operand_stack, ip, fun, arity as usize);
                        let frame = self.call_stack.peek_mut();

                        // Push arguments to locals stack
                        for arg in argv {
                            frame.locals.push(arg);
                        }

                        ip.increment();
                    },
                    Some(Instruction::PopOperand) => {
                        self.operand_stack.pop();
                        ip.increment();
                    },
                    Some(Instruction::PopLocal) => {
                        let frame = self.call_stack.peek_mut();
                        
                        // Pop item from locals
                        frame.locals.pop();

                        ip.increment();
                    },
                    Some(Instruction::PickLocal) => {
                        ip.increment(); 

                        // The next two bytes after a `PickLocal`
                        // instruction are the given index.
                        let bytes: Vec<u8> = fetch_bytes(2, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let idx: u16 = cursor.read_u16::<BigEndian>().unwrap();

                        let frame = self.call_stack.peek_mut();

                        // Pick item on locals stack
                        frame.locals.pick(idx as usize);

                        ip.increment();
                    },
                    Some(Instruction::End) => {
                        let frame = self.call_stack.pop();
                        let scope_type = frame.scope_type.clone();

                        // Replace operand stack with an empty one
                        self.operand_stack = Stack::new();
                        
                        if let Some(return_address) = frame.return_address.clone() {
                            let block_len = fun.fetch_block_len(return_address.ip);

                            // Set ip to the current frame's return address 
                            *ip = return_address;

                            let current_ip = ip.ip;

                            match scope_type {
                                CfOperator::Loop => {
                                    // Push frame back to the call stack
                                    self.call_stack.push(frame);

                                    // Set instruction pointer to the beginning
                                    ip.set_ip(current_ip + 2);
                                },
                                _ => {
                                    // Set instruction pointer to the next 
                                    // instruction after the block.
                                    ip.set_ip(current_ip + block_len);
                                }
                            }
                        } else {
                            // Return address is non-existent. Stop execution in this case.
                            break;
                        }
                    },
                    Some(Instruction::BreakIf) => {
                        ip.increment();

                        let op = fun.fetch(ip.ip);

                        if let Some(instruction) = Instruction::from_repr(op) {
                            let is_comp_operator = COMP_OPS
                                .iter()
                                .any(|o| *o == instruction);

                            if is_comp_operator {
                                let mut operands: Vec<VmValue> = Vec::with_capacity(self.operand_stack.len());
                                let mut operand_stack = self.operand_stack.clone();

                                for _ in 0..operand_stack.len() {
                                    let value = operand_stack.pop();
                                    operands.push(value);
                                }

                                let result = perform_comparison(instruction, operands);

                                // Return to stored caller address if comparison is successful
                                if result {
                                    let frame = self.call_stack.pop();
                                    
                                    // Replace operand stack with an empty one
                                    self.operand_stack = Stack::new();
                                    
                                    if let Some(return_address) = frame.return_address {
                                        let block_len = fun.fetch_block_len(return_address.ip);

                                        // Set ip to the current frame's return address 
                                        *ip = return_address;

                                        let current_ip = ip.ip;

                                        // Set instruction pointer to the next 
                                        // instruction after the block.
                                        ip.set_ip(current_ip + block_len);
                                    } else {
                                        unreachable!();
                                    }
                                } else {
                                    ip.increment();
                                }
                            } else {
                                panic!(format!("Can only receive a comparison operator after `BreakIf`. Got: {:?}", instruction))
                            }
                        } else {
                            panic!("Invalid instruction after `BreakIf`. Expected a comparison operator!");
                        }
                    },
                    Some(Instruction::i32Add) => {
                        perform_addition(Instruction::i32Add, &mut self.operand_stack);
                        ip.increment();
                    },
                    _ => unimplemented!()
                }
            } else {
                unreachable!();
            }
        }

        // Reset VM state
        self.ip = None;
        self.call_stack = Stack::<Frame<VmValue>>::new();
        self.operand_stack = Stack::<VmValue>::new();
        Ok(0)
    }
}

/// Execution logic for instructions
/// that begin a block.
fn handle_begin_block(
    block_type: CfOperator,
    ip: &mut Address, 
    call_stack: &mut Stack<Frame<VmValue>>, 
    fun: &Function, 
    init_argv: &[VmValue]
) {
    let initial_ip = ip.clone();

    ip.increment();

    // The next byte after a begin instruction is the arity of the block.
    let arity = fun.fetch(ip.ip);

    // This is fine since arrays can be passed as arguments.
    if arity > 10 {
        panic!("Arity cannot be greater than 10!");
    }

    match (&block_type, arity, call_stack.len()) {
        // The first begin instruction. With arity 0.
        (&CfOperator::Begin, 0, 0) => {
            // Push initial frame
            call_stack.push(Frame::new(CfOperator::Begin, None, None));
        },
        
        // The first begin instruction. With arity other than 0.
        (&CfOperator::Begin, arity, 0) => {
            panic!(format!("The first begin instruction cannot have an arity other than 0! Received: {}", arity));
        },

        // Loop as first instruction.
        (&CfOperator::Loop, _, 0) => {
            panic!(format!("The first instruction cannot be a loop instruction!"));
        },
        
        // Nested begin/loop instruction. With arity other than 0.
        (_, _, _) => {
            let mut buf: Vec<VmValue> = Vec::with_capacity(arity as usize);

            {
                let frame = call_stack.peek_mut();

                // Push items from local stack to the buffer
                // which will then be placed on the new stack.
                for _ in 0..arity {
                    let item = frame.locals.pop();
                    buf.push(item);
                }

                buf.reverse();
            }

            // Push frame
            call_stack.push(Frame::new(block_type, Some(initial_ip), Some(buf)));
        }
    }

    ip.increment();
}

fn fetch_bytes(amount: usize, ip: &mut Address, fun: &Function) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::with_capacity(amount);

    for i in 0..amount {
        let byte = fun.fetch(ip.ip);
    
        b.push(byte);
        
        if i != amount-1 {
            ip.increment();
        }
    }

    b
}

fn fetch_argv(
    frame: &mut Frame<VmValue>, 
    operand_stack: &mut Stack<VmValue>, 
    ip: &mut Address, 
    fun: &Function, 
    arity: usize
) -> (Vec<VmType>, Vec<VmValue>) {
    let mut argv_types: Vec<VmType> = Vec::with_capacity(arity);  
    let mut argv: Vec<VmValue> = Vec::with_capacity(arity);

    // Fetch argument types
    for _ in 0..arity {
        ip.increment();
        
        let op = fun.fetch(ip.ip);
        let arg = match VmType::from_op(op) {
            Some(result) => result,
            _            => panic!(format!("Invalid argument type in begin block! Received: {}", op))
        };

        argv_types.push(arg);
    }

    // Fetch arguments. Only arrays up to
    // size of 8 are allowed as arguments.
    for t in argv_types.iter() {
        ip.increment();

        match t {
            VmType::I32 => {
                let byte = fun.fetch(ip.ip);

                match Instruction::from_repr(byte) {
                    Some(Instruction::PopLocal) => {
                        let value = frame.locals.pop();

                        if let VmValue::I32(_) = value {
                            argv.push(value);
                        } else {
                            panic!(format!("Popped value that is not i32! Got: {:?}", value));
                        }
                    },
                    Some(Instruction::PopOperand) => {
                        let value = operand_stack.pop();

                        if let VmValue::I32(_) = value {
                            argv.push(value);
                        } else {
                            panic!("Popped value that is not i32!");
                        }
                    },
                    _ => {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                        argv.push(VmValue::I32(val));
                    }
                }
            },
            VmType::I64 => {
                let byte = fun.fetch(ip.ip);

                match Instruction::from_repr(byte) {
                    Some(Instruction::PopLocal) => {
                        let value = frame.locals.pop();

                        if let VmValue::I64(_) = value {
                            argv.push(value);
                        } else {
                            panic!(format!("Popped value that is not i64! Got: {:?}", value));
                        }
                    },
                    Some(Instruction::PopOperand) => {
                        let value = operand_stack.pop();

                        if let VmValue::I64(_) = value {
                            argv.push(value);
                        } else {
                            panic!("Popped value that is not i64!");
                        }
                    },
                    _ => {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                        argv.push(VmValue::I64(val));
                    }
                }
            },
            VmType::F32 => {
                let byte = fun.fetch(ip.ip);

                match Instruction::from_repr(byte) {
                    Some(Instruction::PopLocal) => {
                        let value = frame.locals.pop();

                        if let VmValue::F32(_) = value {
                            argv.push(value);
                        } else {
                            panic!(format!("Popped value that is not f32! Got: {:?}", value));
                        }
                    },
                    Some(Instruction::PopOperand) => {
                        let value = operand_stack.pop();

                        if let VmValue::F32(_) = value {
                            argv.push(value);
                        } else {
                            panic!("Popped value that is not f32!");
                        }
                    },
                    _ => {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                        argv.push(VmValue::F32(val));
                    }
                }
            },
            VmType::F64 => {
                let byte = fun.fetch(ip.ip);

                match Instruction::from_repr(byte) {
                    Some(Instruction::PopLocal) => {
                        let value = frame.locals.pop();

                        if let VmValue::F64(_) = value {
                            argv.push(value);
                        } else {
                            panic!(format!("Popped value that is not f64! Got: {:?}", value));
                        }
                    },
                    Some(Instruction::PopOperand) => {
                        let value = operand_stack.pop();

                        if let VmValue::F64(_) = value {
                            argv.push(value);
                        } else {
                            panic!("Popped value that is not f64!");
                        }
                    },
                    _ => {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                        argv.push(VmValue::F64(val));
                    }
                }
            },
            VmType::i32Array2 => {
                let mut result: [i32; 2] = [0; 2];
                let mut buffer: Vec<i32> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::I32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not i32! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::I32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i32Array2(result));
            },
            VmType::i32Array4 => {
                let mut result: [i32; 4] = [0; 4];
                let mut buffer: Vec<i32> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::I32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not i32! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::I32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i32Array4(result));
            },
            VmType::i32Array8 => {
                let mut result: [i32; 8] = [0; 8];
                let mut buffer: Vec<i32> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::I32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not i32! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::I32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i32Array8(result));
            },
            VmType::i64Array2 => {
                let mut result: [i64; 2] = [0; 2];
                let mut buffer: Vec<i64> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::I64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not i64! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::I64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i64Array2(result));
            },
            VmType::i64Array4 => {
                let mut result: [i64; 4] = [0; 4];
                let mut buffer: Vec<i64> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::I64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not i64! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::I64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i64Array4(result));
            },
            VmType::i64Array8 => {
                let mut result: [i64; 8] = [0; 8];
                let mut buffer: Vec<i64> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::I64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not i64! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::I64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i64Array8(result));
            },
            VmType::f32Array2 => {
                let mut result: [f32; 2] = [0.0; 2];
                let mut buffer: Vec<f32> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::F32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not f32! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::F32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not f32!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f32Array2(result));
            },
            VmType::f32Array4 => {
                let mut result: [f32; 4] = [0.0; 4];
                let mut buffer: Vec<f32> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::F32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not f32! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::F32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not f32!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f32Array4(result));
            },
            VmType::f32Array8 => {
                let mut result: [f32; 8] = [0.0; 8];
                let mut buffer: Vec<f32> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::F32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not f32! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::F32(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not f32!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f32Array8(result));
            },
            VmType::f64Array2 => {
                let mut result: [f64; 2] = [0.0; 2];
                let mut buffer: Vec<f64> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::F64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not f64! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::F64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not f64!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f64Array2(result));
            },
            VmType::f64Array4 => {
                let mut result: [f64; 4] = [0.0; 4];
                let mut buffer: Vec<f64> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::F64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not f64! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::F64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not f64!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f64Array4(result));
            },
            VmType::f64Array8 => {
                let mut result: [f64; 8] = [0.0; 8];
                let mut buffer: Vec<f64> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    match Instruction::from_repr(byte) {
                        Some(Instruction::PopLocal) => {
                            let value = frame.locals.pop();

                            if let VmValue::F64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!(format!("Popped value that is not f64! Got: {:?}", value));
                            }
                        },
                        Some(Instruction::PopOperand) => {
                            let value = operand_stack.pop();

                            if let VmValue::F64(result) = value {
                                buffer.push(result);
                            } else {
                                panic!("Popped value that is not f64!");
                            }
                        },
                        _ => {
                            let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                            let mut cursor = Cursor::new(&bytes);
                            let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                            buffer.push(val);
                        }
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f64Array8(result));
            },
            op => {
                panic!(format!("Invalid argument type in begin block! Received: {:?}", op));
            }
        }
    }

    (argv_types, argv)
}

fn perform_comparison(op: Instruction, operands: Vec<VmValue>) -> bool {
    if operands.len() < 2 {
        panic!(format!("Cannot perform comparison on less than 2 operands! Got: {}", operands.len()));
    }

    match op {
        Instruction::i32Eq
        | Instruction::i64Eq
        | Instruction::f32Eq
        | Instruction::f64Eq => {
            let (result, _) = operands
                .iter()
                .fold((true, None), |(result, last), op| {
                    if let Some(last) = last {
                        if result {
                            (op == last, Some(op))
                        } else {
                            (result, Some(op))
                        }
                    } else {
                        (result, Some(op))
                    }
                });

            result
        },
        _ => unimplemented!()
    }
}

// TODO: Handle overflow
fn perform_addition(op: Instruction, operand_stack: &mut Stack<VmValue>) {
    let len = operand_stack.len();

    if len < 2 {
        panic!(format!("Cannot perform addition on less than 2 operands! Got: {}", len));
    }

    match op {
        Instruction::i32Add
        | Instruction::i64Add
        | Instruction::f32Add
        | Instruction::f64Add => {
            let mut buf: Vec<VmValue> = Vec::with_capacity(len);

            // Move items from operand stack to buffer
            for _ in 0..len {
                buf.push(operand_stack.pop());
            }

            // Perform addition
            let result = buf
                .iter()
                .fold(None, |acc: Option<VmValue>, x| {
                    if let Some(acc) = acc {
                        Some(acc + *x)
                    } else {
                        Some(*x)
                    }
                });

            // Push result back to operand stack
            if let Some(result) = result {
                operand_stack.push(result);
            } else {
                unreachable!();
            }
        },
        _ => panic!(format!("Must receive an addition instruction! Got: {:?}", op))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Hash;

    #[test]
    #[should_panic(expected = "first instruction cannot be a loop instruction")]
    fn it_fails_with_first_loop_instruction() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Loop.repr(),
            0x00,
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: VmType::I32,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_fails_with_first_begin_arity_other_than_zero() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Loop.repr(),
            0x01,                        // Arity 1
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: VmType::I32,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "Arity cannot be greater than 10!")]
    fn it_fails_with_begin_arity_greater_than_ten() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x03,                             // 3 Arity
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
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::Begin.repr(),
            0x1b,                             // 11 arity. The latest 11 items on the caller stack will be pushed to the new frame
            Instruction::Nop.repr(),
            Instruction::End.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: VmType::I32,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], 0).unwrap();
    }

    #[test]
    fn it_executes_correctly() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x03,                             // 3 Arity
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
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::Begin.repr(),
            0x05,                            // 5 arity. The latest 5 items on the caller stack will be pushed to the new frame
            Instruction::PopLocal.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: VmType::I32,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], 0).unwrap();

        assert!(true);
    }

    #[test]
    fn it_executes_correctly_with_loops() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushLocal.repr(),
            0x03,                             // 3 Arity
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
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PickLocal.repr(),
            0x00,
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x02,
            Instruction::PushLocal.repr(),   // Push loop counter to locals stack
            0x01,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Loop.repr(),
            0x05,                            // 5 arity. The latest 5 items on the caller stack will be pushed to the new frame
            Instruction::PushOperand.repr(), 
            0x02,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),    // Push counter to operand stack
            0x00,                            // Loop 5 times
            0x00,
            0x00,
            0x04,
            Instruction::BreakIf.repr(),     // Break if items on the operand stack are equal  
            Instruction::i32Eq.repr(),
            Instruction::PopOperand.repr(),
            Instruction::PushOperand.repr(), // Increment counter
            0x01,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::i32Add.repr(),
            Instruction::PushLocal.repr(),   // Move counter from operand stack back to call stack
            0x01,
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
            return_type: VmType::I32,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], 0).unwrap();

        assert!(true);
    }
}