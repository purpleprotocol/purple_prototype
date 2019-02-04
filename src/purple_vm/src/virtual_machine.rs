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
use instruction_set::Instruction;
use patricia_trie::{TrieMut, TrieDBMut};
use persistence::{BlakeDbHasher, Codec};
use byteorder::{BigEndian, ReadBytesExt};
use error::VmError;
use std::io::Cursor;

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
        init_argv: &[VmValue], 
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

                match Instruction::from_repr(op) {
                    Some(Instruction::Begin) => {
                        let initial_ip = ip.clone();

                        ip.increment();

                        // The next byte after a begin instruction is the arity of the block.
                        let arity = fun.fetch(ip.ip);

                        // This is fine since arrays can be passed as arguments.
                        if arity > 10 {
                            panic!("Arity cannot be greater than 10!");
                        }

                        let mut argv_types: Vec<VmType> = Vec::with_capacity(arity as usize);  
                        let mut argv: Vec<VmValue> = Vec::with_capacity(arity as usize);

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
                        for t in argv_types {
                            ip.increment();

                            match t {
                                VmType::I32 => {
                                    let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                    let mut cursor = Cursor::new(&bytes);
                                    let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                                    argv.push(VmValue::I32(val));
                                },
                                VmType::I64 => {
                                    let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                    let mut cursor = Cursor::new(&bytes);
                                    let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                                    argv.push(VmValue::I64(val));
                                },
                                VmType::F32 => {
                                    let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                    let mut cursor = Cursor::new(&bytes);
                                    let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                                    argv.push(VmValue::F32(val));
                                },
                                VmType::F64 => {
                                    let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                    let mut cursor = Cursor::new(&bytes);
                                    let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                                    argv.push(VmValue::F64(val));
                                },
                                VmType::I32Array2 => {
                                    let mut result: [i32; 2] = [0; 2];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(2);
                                    let mut buffer2: Vec<i32> = Vec::with_capacity(2);

                                    // Get binaries
                                    for _ in 0..2 {
                                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::I32Array2(result));
                                },
                                VmType::I32Array4 => {
                                    let mut result: [i32; 4] = [0; 4];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(4);
                                    let mut buffer2: Vec<i32> = Vec::with_capacity(4);

                                    // Get binaries
                                    for _ in 0..4 {
                                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::I32Array4(result));
                                },
                                VmType::I32Array8 => {
                                    let mut result: [i32; 8] = [0; 8];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(8);
                                    let mut buffer2: Vec<i32> = Vec::with_capacity(8);

                                    // Get binaries
                                    for _ in 0..8 {
                                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::I32Array8(result));
                                },
                                VmType::I64Array2 => {
                                    let mut result: [i64; 2] = [0; 2];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(2);
                                    let mut buffer2: Vec<i64> = Vec::with_capacity(2);

                                    // Get binaries
                                    for _ in 0..2 {
                                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::I64Array2(result));
                                },
                                VmType::I64Array4 => {
                                    let mut result: [i64; 4] = [0; 4];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(4);
                                    let mut buffer2: Vec<i64> = Vec::with_capacity(4);

                                    // Get binaries
                                    for _ in 0..4 {
                                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::I64Array4(result));
                                },
                                VmType::I64Array8 => {
                                    let mut result: [i64; 8] = [0; 8];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(8);
                                    let mut buffer2: Vec<i64> = Vec::with_capacity(8);

                                    // Get binaries
                                    for _ in 0..8 {
                                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::I64Array8(result));
                                },
                                VmType::F32Array2 => {
                                    let mut result: [f32; 2] = [0.0; 2];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(2);
                                    let mut buffer2: Vec<f32> = Vec::with_capacity(2);

                                    // Get binaries
                                    for _ in 0..2 {
                                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::F32Array2(result));
                                },
                                VmType::F32Array4 => {
                                    let mut result: [f32; 4] = [0.0; 4];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(4);
                                    let mut buffer2: Vec<f32> = Vec::with_capacity(4);

                                    // Get binaries
                                    for _ in 0..4 {
                                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::F32Array4(result));
                                },
                                VmType::F32Array8 => {
                                    let mut result: [f32; 8] = [0.0; 8];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(8);
                                    let mut buffer2: Vec<f32> = Vec::with_capacity(8);

                                    // Get binaries
                                    for _ in 0..8 {
                                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::F32Array8(result));
                                },
                                VmType::F64Array2 => {
                                    let mut result: [f64; 2] = [0.0; 2];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(2);
                                    let mut buffer2: Vec<f64> = Vec::with_capacity(2);

                                    // Get binaries
                                    for _ in 0..2 {
                                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::F64Array2(result));
                                },
                                VmType::F64Array4 => {
                                    let mut result: [f64; 4] = [0.0; 4];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(4);
                                    let mut buffer2: Vec<f64> = Vec::with_capacity(4);

                                    // Get binaries
                                    for _ in 0..4 {
                                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::F64Array4(result));
                                },
                                VmType::F64Array8 => {
                                    let mut result: [f64; 8] = [0.0; 8];
                                    let mut buffer1: Vec<Vec<u8>> = Vec::with_capacity(8);
                                    let mut buffer2: Vec<f64> = Vec::with_capacity(8);

                                    // Get binaries
                                    for _ in 0..8 {
                                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                                        buffer1.push(bytes);
                                    }

                                    // Decode bytes
                                    for b in buffer1 {
                                        let mut cursor = Cursor::new(&b);
                                        let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                                        buffer2.push(val);
                                    }

                                    // Push argument
                                    result.copy_from_slice(&buffer2);
                                    argv.push(VmValue::F64Array8(result));
                                },
                                op => {
                                    panic!(format!("Invalid argument type in begin block! Received: {:?}", op));
                                }
                            }
                        }

                        match (arity, self.call_stack.len()) {
                            // The first begin instruction. With arity 0.
                            (0, 0) => {
                                // Push initial frame
                                self.call_stack.push(Frame::new(CfOperator::Begin, None));

                                let frame = self.call_stack.peek_mut();

                                // Push args to frame
                                for arg in init_argv {
                                    frame.locals.push(*arg);
                                }
                            },

                            // Nested begin instruction. With arity 0.
                            (0, _) => {
                                // Push frame
                                self.call_stack.push(Frame::new(CfOperator::Begin, Some(ip.clone())));
                            },
                            
                            // The first begin instruction. With arity other than 0.
                            (arity, 0) => {
                                panic!(format!("The first begin instruction cannot have an arity other than 0! Received: {}", arity));
                            },
                            
                            // Nested begin instruction. With arity other than 0.
                            (_, _) => {
                                // Push frame
                                self.call_stack.push(Frame::new(CfOperator::Begin, Some(ip.clone())));

                                let frame = self.call_stack.peek_mut();

                                // Push args to frame
                                for arg in argv {
                                    frame.locals.push(arg);
                                }
                            }
                        }

                        ip.increment();
                    },
                    _ => unimplemented!()
                }
            } else {
                unreachable!();
            }
        }
    }
}

fn fetch_bytes(amount: usize, ip: &mut Address, fun: &Function) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::with_capacity(amount);

    for _ in 0..amount {
        let byte = fun.fetch(ip.ip);
    
        b.push(byte);
        ip.increment();
    }

    b
}