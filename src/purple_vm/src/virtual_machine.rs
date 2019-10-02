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

use address::Address;
use bitvec::Bits;
use byteorder::{BigEndian, ReadBytesExt};
use code::function::Function;
use error::VmError;
use frame::Frame;
use gas::Gas;
use instruction_set::{Instruction, COMP_OPS};
use module::Module;
use patricia_trie::TrieDBMut;
use persistence::{BlakeDbHasher, Codec};
use primitives::control_flow::CfOperator;
use primitives::r#type::VmType;
use primitives::value::VmValue;
use stack::Stack;
use std::io::Cursor;

const MAX_OP_ARITY: u8 = 8;

#[derive(Debug)]
pub struct Vm {
    ip: Option<Address>,
    modules: Vec<Module>,
    call_stack: Stack<Frame<VmValue>>,
    operand_stack: Stack<VmValue>,
    heap: Vec<Vec<Option<VmValue>>>,
}

impl Vm {
    pub fn new() -> Vm {
        let mut heap = Vec::with_capacity(256);

        for _ in 0..256 {
            heap.push(vec![None; 256]);
        }

        Vm {
            modules: Vec::new(),
            ip: None,
            heap: heap,
            call_stack: Stack::<Frame<VmValue>>::new(),
            operand_stack: Stack::<VmValue>::new(),
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
        gas: Gas,
    ) -> Result<Gas, VmError> {
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

                println!("DEBUG IP: {}, FUN IDX: {}", ip.ip, ip.fun_idx);
                match Instruction::from_repr(op) {
                    Some(Instruction::Halt) => {
                        break;
                    }
                    Some(Instruction::Nop) => {
                        // This does nothing. Just increment the instruction pointer.
                        ip.increment();
                    }
                    Some(Instruction::Call) => {
                        let mut buf: Vec<u8> = Vec::with_capacity(2);

                        // Fetch fun idx
                        for _ in 0..2 {
                            ip.increment();
                            let byte = fun.fetch(ip.ip);
                            buf.push(byte);
                        }

                        ip.increment();

                        let return_ip = ip.clone();
                        let idx: usize = decode_be_u16!(&buf).unwrap() as usize;
                        let fun = &module.functions[idx];
                        let mut argv: Vec<VmValue> = Vec::with_capacity(fun.arity as usize);

                        // Fetch call args
                        for _ in 0..fun.arity {
                            let frame = self.call_stack.peek_mut();
                            let val = frame.locals.pop();

                            argv.push(val);
                        }

                        argv.reverse();

                        // Push new frame to call stack
                        self.call_stack
                            .push(Frame::new(None, Some(return_ip), Some(argv)));

                        // Set new ip
                        ip.ip = 2;
                        ip.fun_idx = idx;
                    }
                    Some(Instruction::Return) => {
                        ip.increment();

                        // Fetch the number of returned values
                        let return_arity = fun.fetch(ip.ip);
                        let mut frame = self.call_stack.pop();
                        let return_address = frame.return_address.clone();
                        let mut return_values: Vec<VmValue> =
                            Vec::with_capacity(return_arity as usize);

                        // Move return values to buffer
                        for _ in 0..return_arity {
                            let value = frame.locals.pop();
                            return_values.push(value);
                        }

                        return_values.reverse();

                        if frame.scope_type.is_none() {
                            let frame = self.call_stack.peek_mut();

                            // Push return values to returned frame
                            for val in return_values.iter() {
                                frame.locals.push(*val);
                            }

                            // Replace operand stack with an empty one
                            self.operand_stack = Stack::new();

                            if let Some(return_address) = return_address.clone() {
                                // Set ip to the current frame's return address
                                *ip = return_address;
                            }
                        } else {
                            // Pop frames until we reach one without a scope type
                            loop {
                                let frame = self.call_stack.pop();
                                let return_address = frame.return_address.clone();

                                if frame.scope_type.is_none() {
                                    let frame = self.call_stack.peek_mut();

                                    // Push return values to returned frame
                                    for val in return_values.iter() {
                                        frame.locals.push(*val);
                                    }

                                    // Replace operand stack with an empty one
                                    self.operand_stack = Stack::new();

                                    if let Some(return_address) = return_address {
                                        // Set ip to the current frame's return address
                                        *ip = return_address;
                                    }

                                    break;
                                }
                            }
                        }
                    }
                    Some(Instruction::Begin) => {
                        handle_begin_block(
                            CfOperator::Begin,
                            ip,
                            &mut self.call_stack,
                            &mut self.operand_stack,
                            &fun,
                            &argv,
                        )?;
                    }
                    Some(Instruction::Loop) => {
                        handle_begin_block(
                            CfOperator::Loop,
                            ip,
                            &mut self.call_stack,
                            &mut self.operand_stack,
                            &fun,
                            &argv,
                        )?;
                    }
                    Some(Instruction::If) => {
                        handle_begin_block(
                            CfOperator::If,
                            ip,
                            &mut self.call_stack,
                            &mut self.operand_stack,
                            &fun,
                            &argv,
                        )?;
                    }
                    Some(Instruction::Else) => {
                        handle_begin_block(
                            CfOperator::Else,
                            ip,
                            &mut self.call_stack,
                            &mut self.operand_stack,
                            &fun,
                            &argv,
                        )?;
                    }
                    Some(Instruction::PushOperand) => {
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
                        let result = fetch_argv(
                            frame,
                            &mut self.operand_stack,
                            ip,
                            &mut self.heap,
                            fun,
                            arity as usize,
                        );

                        match result {
                            Ok((_, argv)) => {
                                // Push arguments to operand stack
                                for arg in argv {
                                    self.operand_stack.push(arg);
                                }

                                ip.increment();
                            }
                            Err(err) => return Err(err),
                        }
                    }
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
                        let result = fetch_argv(
                            self.call_stack.peek_mut(),
                            &mut self.operand_stack,
                            ip,
                            &mut self.heap,
                            fun,
                            arity as usize,
                        );

                        match result {
                            Ok((_, argv)) => {
                                let frame = self.call_stack.peek_mut();

                                // Push arguments to locals stack
                                for arg in argv {
                                    frame.locals.push(arg);
                                }

                                ip.increment();
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    Some(Instruction::PopOperand) => {
                        self.operand_stack.pop();
                        ip.increment();
                    }
                    Some(Instruction::PopLocal) => {
                        let frame = self.call_stack.peek_mut();

                        // Pop item from locals
                        frame.locals.pop();

                        ip.increment();
                    }
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
                    }
                    Some(Instruction::PickOperand) => {
                        ip.increment();

                        // The next two bytes after a `PickOperand`
                        // instruction are the given index.
                        let bytes: Vec<u8> = fetch_bytes(2, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let idx: u16 = cursor.read_u16::<BigEndian>().unwrap();

                        // Pick item on operand stack
                        self.operand_stack.pick(idx as usize);

                        ip.increment();
                    }
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
                                Some(CfOperator::Loop) => {
                                    // Push frame back to the call stack
                                    self.call_stack.push(frame);

                                    // Set instruction pointer to the beginning
                                    ip.set_ip(current_ip + 2);
                                }
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
                    }
                    Some(Instruction::Break) => {
                        // Pop frames until one has a `Loop` scope type
                        loop {
                            let frame = self.call_stack.pop();

                            if let Some(CfOperator::Loop) = frame.scope_type {
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

                                break;
                            }
                        }
                    }
                    Some(Instruction::BreakIf) => {
                        ip.increment();

                        let op = fun.fetch(ip.ip);

                        if let Some(instruction) = Instruction::from_repr(op) {
                            let is_comp_operator = COMP_OPS.iter().any(|o| *o == instruction);

                            if is_comp_operator {
                                let mut operands: Vec<VmValue> =
                                    Vec::with_capacity(self.operand_stack.len());
                                let mut operand_stack = self.operand_stack.clone();

                                for _ in 0..operand_stack.len() {
                                    let value = operand_stack.pop();
                                    operands.push(value);
                                }

                                let result = perform_comparison(instruction, operands)?;

                                // Return to stored caller address if comparison is successful
                                if result {
                                    // Pop frames until we find one with a `Loop` scope type
                                    loop {
                                        let frame = self.call_stack.pop();

                                        if let Some(CfOperator::Loop) = frame.scope_type {
                                            // Replace operand stack with an empty one
                                            self.operand_stack = Stack::new();

                                            if let Some(return_address) = frame.return_address {
                                                let block_len =
                                                    fun.fetch_block_len(return_address.ip);

                                                // Set ip to the current frame's return address
                                                *ip = return_address;

                                                let current_ip = ip.ip;

                                                // Set instruction pointer to the next
                                                // instruction after the block.
                                                ip.set_ip(current_ip + block_len);
                                            } else {
                                                unreachable!();
                                            }

                                            break;
                                        }
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
                    }
                    Some(Instruction::Eq) => {
                        let os = self.operand_stack.to_vec();

                        // Perform assertion
                        if perform_comparison(Instruction::Eq, os)? {
                            ip.increment();
                        } else {
                            return Err(VmError::AssertionFailed);
                        }
                    }
                    Some(Instruction::Add) => {
                        perform_addition(Instruction::Add, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Sub) => {
                        perform_substraction(Instruction::Sub, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Mul) => {
                        perform_multiplication(Instruction::Mul, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::DivSigned) => {
                        perform_div_signed(Instruction::DivSigned, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::DivUnsigned) => {
                        perform_div_unsigned(Instruction::DivUnsigned, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::RemSigned) => {
                        perform_rem_signed(Instruction::RemSigned, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::RemUnsigned) => {
                        perform_rem_unsigned(Instruction::RemUnsigned, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Min) => {
                        perform_min(Instruction::Min, &mut self.operand_stack);
                        ip.increment();
                    }
                    Some(Instruction::Max) => {
                        perform_max(Instruction::Max, &mut self.operand_stack);
                        ip.increment();
                    }
                    Some(Instruction::Abs) => {
                        perform_float_common(Instruction::Abs, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Neg) => {
                        perform_float_common(Instruction::Neg, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Div) => {
                        perform_float_common(Instruction::Div, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Ceil) => {
                        perform_float_common(Instruction::Ceil, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Floor) => {
                        perform_float_common(Instruction::Floor, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Trunc) => {
                        perform_float_common(Instruction::Trunc, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Nearest) => {
                        perform_float_common(Instruction::Nearest, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::CopySign) => {
                        perform_float_common(Instruction::CopySign, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Sqrt) => {
                        perform_float_common(Instruction::Sqrt, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::And) => {
                        perform_integer_common(Instruction::And, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Or) => {
                        perform_integer_common(Instruction::Or, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Xor) => {
                        perform_integer_common(Instruction::Xor, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Shl) => {
                        perform_integer_common(Instruction::Shl, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::ShrSigned) => {
                        perform_integer_common(Instruction::ShrSigned, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::ShrUnsigned) => {
                        perform_integer_common(Instruction::ShrUnsigned, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Rotl) => {
                        perform_integer_common(Instruction::Rotl, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::Rotr) => {
                        perform_integer_common(Instruction::Rotr, &mut self.operand_stack)?;
                        ip.increment();
                    }
                    Some(Instruction::i32Store)
                    | Some(Instruction::i64Store)
                    | Some(Instruction::f32Store)
                    | Some(Instruction::f64Store) => {
                        if self.operand_stack.is_empty() {
                            panic!("The operand stack cannot be empty when calling a store instruction!");
                        }

                        // Fetch stored item
                        let elem = self.operand_stack.pop();

                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Store to heap
                        self.heap[x][y] = Some(elem);

                        ip.increment();
                    }

                    // 8bits store ops
                    Some(Instruction::i32Store8) | Some(Instruction::i64Store8) => {
                        if self.operand_stack.is_empty() {
                            panic!("The operand stack cannot be empty when calling a store instruction!");
                        }

                        // Fetch stored item
                        let elem = self.operand_stack.pop();

                        if let VmValue::I32(inner) = elem {
                            if inner > std::u8::MAX as i32 || inner < std::i8::MIN as i32 {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot store a value other than i32!");
                        }

                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Store to heap
                        self.heap[x][y] = Some(elem);

                        ip.increment();
                    }

                    // 16bits store ops
                    Some(Instruction::i32Store16) | Some(Instruction::i64Store16) => {
                        if self.operand_stack.is_empty() {
                            panic!("The operand stack cannot be empty when calling a store instruction!");
                        }

                        // Fetch stored item
                        let elem = self.operand_stack.pop();

                        if let VmValue::I32(inner) = elem {
                            if inner > std::u16::MAX as i32 || inner < std::i16::MIN as i32 {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot store a value other than i32!");
                        }

                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Store to heap
                        self.heap[x][y] = Some(elem);

                        ip.increment();
                    }

                    // 32bits store
                    Some(Instruction::i64Store32) => {
                        if self.operand_stack.is_empty() {
                            panic!("The operand stack cannot be empty when calling a store instruction!");
                        }

                        // Fetch stored item
                        let elem = self.operand_stack.pop();

                        if let VmValue::I64(inner) = elem {
                            if inner > std::u32::MAX as i64 || inner < std::i32::MIN as i64 {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot store a value other than i64!");
                        }

                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Store to heap
                        self.heap[x][y] = Some(elem);

                        ip.increment();
                    }

                    Some(Instruction::i32Load)
                    | Some(Instruction::i64Load)
                    | Some(Instruction::f32Load)
                    | Some(Instruction::f64Load) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        // Set heap location to `None`
                        self.heap[x][y] = None;

                        // Push element to operand stack
                        self.operand_stack.push(elem);

                        ip.increment();
                    }

                    Some(Instruction::i32Load8Signed) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I32(inner) = elem {
                            if inner > std::i8::MAX as i32 || inner < std::i8::MIN as i32 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i32!");
                        }
                    }

                    Some(Instruction::i32Load8Unsigned) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I32(inner) = elem {
                            if inner > std::u8::MAX as i32 || inner < std::u8::MIN as i32 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i32!");
                        }
                    }

                    Some(Instruction::i32Load16Signed) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I32(inner) = elem {
                            if inner > std::i16::MAX as i32 || inner < std::i16::MIN as i32 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i32!");
                        }
                    }

                    Some(Instruction::i32Load16Unsigned) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I32(inner) = elem {
                            if inner > std::u16::MAX as i32 || inner < std::u16::MIN as i32 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i32!");
                        }
                    }

                    Some(Instruction::i64Load8Signed) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I64(inner) = elem {
                            if inner > std::i8::MAX as i64 || inner < std::i8::MIN as i64 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i64!");
                        }
                    }

                    Some(Instruction::i64Load8Unsigned) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I64(inner) = elem {
                            if inner > std::u8::MAX as i64 || inner < std::u8::MIN as i64 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i64!");
                        }
                    }

                    Some(Instruction::i64Load16Signed) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I64(inner) = elem {
                            if inner > std::i16::MAX as i64 || inner < std::i16::MIN as i64 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i64!");
                        }
                    }

                    Some(Instruction::i64Load16Unsigned) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I64(inner) = elem {
                            if inner > std::u16::MAX as i64 || inner < std::u16::MIN as i64 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i64!");
                        }
                    }

                    Some(Instruction::i64Load32Signed) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I64(inner) = elem {
                            if inner > std::i32::MAX as i64 || inner < std::i32::MIN as i64 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i64!");
                        }
                    }

                    Some(Instruction::i64Load32Unsigned) => {
                        // Fetch coordinates
                        ip.increment();
                        let x = fun.fetch(ip.ip) as usize;
                        ip.increment();
                        let y = fun.fetch(ip.ip) as usize;

                        // Fetch elem
                        let elem = self.heap[x][y].unwrap();

                        if let VmValue::I64(inner) = elem {
                            if inner > std::u32::MAX as i64 || inner < std::u32::MIN as i64 {
                                // Set heap location to `None`
                                self.heap[x][y] = None;

                                // Push element to operand stack
                                self.operand_stack.push(elem);

                                ip.increment();
                            } else {
                                return Err(VmError::Overflow);
                            }
                        } else {
                            panic!("Cannot receive value other than i64!");
                        }
                    }
                    _ => unimplemented!(),
                }
            } else {
                unreachable!();
            }
        }

        // Reset VM state
        self.ip = None;
        self.call_stack = Stack::<Frame<VmValue>>::new();
        self.operand_stack = Stack::<VmValue>::new();

        Ok(Gas::from_bytes(b"0.0").unwrap())
    }
}

/// Execution logic for instructions
/// that begin a block.
fn handle_begin_block(
    block_type: CfOperator,
    ip: &mut Address,
    call_stack: &mut Stack<Frame<VmValue>>,
    operand_stack: &mut Stack<VmValue>,
    fun: &Function,
    init_argv: &[VmValue],
) -> Result<(), VmError> {
    let initial_ip = ip.clone();

    ip.increment();

    // The next byte after a begin instruction is the arity of the block.
    let arity = fun.fetch(ip.ip);

    match (&block_type, arity, call_stack.len()) {
        // The first begin instruction. With arity 0.
        (&CfOperator::Begin, 0, 0) => {
            // Push initial frame
            call_stack.push(Frame::new(
                Some(CfOperator::Begin),
                None,
                Some(init_argv.to_vec()),
            ));
        }

        // The first begin instruction. With arity other than 0.
        (&CfOperator::Begin, arity, 0) => {
            panic!(format!(
                "The first begin instruction cannot have an arity other than 0! Received: {}",
                arity
            ));
        }

        // Loop as first instruction.
        (&CfOperator::Loop, _, 0) => {
            panic!("The first instruction cannot be a Loop instruction!");
        }

        // If as first instruction.
        (&CfOperator::If, _, 0) => {
            panic!("The first instruction cannot be an If instruction!");
        }

        // Nested if instruction. With arity 0.
        (&CfOperator::If, 0, _) => {
            ip.increment();
            let op = fun.fetch(ip.ip);

            if let Some(instruction) = Instruction::from_repr(op) {
                let is_comp_operator = COMP_OPS.iter().any(|o| *o == instruction);

                if is_comp_operator {
                    let mut operands: Vec<VmValue> = Vec::with_capacity(operand_stack.len());
                    let mut os = operand_stack.clone();

                    for _ in 0..os.len() {
                        let value = os.pop();
                        operands.push(value);
                    }
                    if perform_comparison(instruction, operands)? {
                        // Push frame
                        call_stack.push(Frame::new(Some(CfOperator::If), Some(initial_ip), None));
                    } else {
                        let block_len = fun.fetch_block_len(initial_ip.ip);
                        let op = fun.fetch(initial_ip.ip + block_len);

                        // Determine if the `If` block has a
                        // corresponding `Else` block to which
                        // we can jump to.
                        if let Some(Instruction::Else) = Instruction::from_repr(op) {
                            ip.set_ip(initial_ip.ip + block_len);
                            handle_begin_block(
                                CfOperator::Else,
                                ip,
                                call_stack,
                                operand_stack,
                                fun,
                                init_argv,
                            )?;
                        }
                    }
                } else {
                    panic!(format!(
                        "Can only receive a comparison operator after `If`. Got: {:?}",
                        instruction
                    ))
                }
            } else {
                unreachable!();
            }
        }

        // Nested if instruction. With arity other than 0.
        (&CfOperator::If, arity, _) => {
            ip.increment();
            let op = fun.fetch(ip.ip);

            if let Some(instruction) = Instruction::from_repr(op) {
                let is_comp_operator = COMP_OPS.iter().any(|o| *o == instruction);

                if is_comp_operator {
                    let mut operands: Vec<VmValue> = Vec::with_capacity(operand_stack.len());
                    let mut os = operand_stack.clone();

                    for _ in 0..os.len() {
                        let value = os.pop();
                        operands.push(value);
                    }
                    if perform_comparison(instruction, operands)? {
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
                        call_stack.push(Frame::new(
                            Some(CfOperator::If),
                            Some(initial_ip),
                            Some(buf),
                        ));
                    } else {
                        let block_len = fun.fetch_block_len(initial_ip.ip);
                        let op = fun.fetch(initial_ip.ip + block_len);

                        // Determine if the `If` block has a
                        // corresponding `Else` block to which
                        // we can jump to.
                        if let Some(Instruction::Else) = Instruction::from_repr(op) {
                            ip.set_ip(initial_ip.ip + block_len);
                            handle_begin_block(
                                CfOperator::Else,
                                ip,
                                call_stack,
                                operand_stack,
                                fun,
                                init_argv,
                            )?;
                        }
                    }
                } else {
                    panic!(format!(
                        "Can only receive a comparison operator after `If`. Got: {:?}",
                        instruction
                    ))
                }
            } else {
                unreachable!();
            }
        }

        // Nested begin/loop instruction. With arity 0.
        (block_type, 0, _) => {
            // Push frame
            call_stack.push(Frame::new(Some(block_type.clone()), Some(initial_ip), None));
        }

        // Nested begin/loop instruction. With arity other than 0.
        (block_type, _, _) => {
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
            call_stack.push(Frame::new(
                Some(block_type.clone()),
                Some(initial_ip),
                Some(buf),
            ));
        }
    }

    if let CfOperator::Else = block_type {
        // Do nothing
    } else {
        ip.increment();
    }

    Ok(())
}

fn fetch_bytes(amount: usize, ip: &mut Address, fun: &Function) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::with_capacity(amount);

    for i in 0..amount {
        let byte = fun.fetch(ip.ip);

        b.push(byte);

        if i != amount - 1 {
            ip.increment();
        }
    }

    b
}

#[derive(Clone, Debug)]
enum ArgLocation {
    Inline,
    Memory,
}

fn fetch_argv(
    frame: &mut Frame<VmValue>,
    operand_stack: &mut Stack<VmValue>,
    ip: &mut Address,
    heap: &mut Vec<Vec<Option<VmValue>>>,
    fun: &Function,
    arity: usize,
) -> Result<(Vec<VmType>, Vec<VmValue>), VmError> {
    let mut argv_types: Vec<(VmType, ArgLocation)> = Vec::with_capacity(arity);
    let mut argv: Vec<VmValue> = Vec::with_capacity(arity);

    ip.increment();

    // The next byte contains the arg locations
    let args_bitmask = fun.fetch(ip.ip);

    // Fetch argument types
    for i in 0..arity {
        ip.increment();

        let op = fun.fetch(ip.ip);
        let arg = match VmType::from_op(op) {
            Some(result) => result,
            _ => panic!(format!("Invalid argument type! Received: {}", op)),
        };

        let arg_type = if args_bitmask.get(i as u8) {
            ArgLocation::Memory
        } else {
            ArgLocation::Inline
        };

        argv_types.push((arg, arg_type));
    }

    // Fetch arguments. Only arrays up to
    // size of 8 are allowed as arguments.
    for (t, al) in argv_types.iter() {
        ip.increment();

        match t {
            VmType::I32 => {
                let byte = fun.fetch(ip.ip);

                // Fetch value from memory
                if let ArgLocation::Memory = al {
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
                        Some(Instruction::i32Load) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I32(_) = value {
                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        Some(Instruction::i32Load8Signed) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I32(inner) = value {
                                if inner > std::i8::MAX as i32 || inner < std::i8::MIN as i32 {
                                    return Err(VmError::Overflow);
                                }
                            
                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        Some(Instruction::i32Load8Unsigned) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I32(inner) = value {
                                if inner > std::u8::MAX as i32 || inner < std::u8::MIN as i32 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        Some(Instruction::i32Load16Signed) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I32(inner) = value {
                                if inner > std::i16::MAX as i32 || inner < std::i16::MIN as i32 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        Some(Instruction::i32Load16Unsigned) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I32(inner) = value {
                                if inner > std::u16::MAX as i32 || inner < std::u16::MIN as i32 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i32!");
                            }
                        },
                        Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                        _        => panic!("Cannot fetch from memory! Invalid instruction!")
                    }
                } else {
                    let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                    let mut cursor = Cursor::new(&bytes);
                    let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                    argv.push(VmValue::I32(val));
                }
            }
            VmType::I64 => {
                let byte = fun.fetch(ip.ip);

                // Fetch value from memory
                if let ArgLocation::Memory = al {
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
                        Some(Instruction::i64Load) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I64(_) = value {
                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        Some(Instruction::i64Load8Signed) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I64(inner) = value {
                                if inner > std::i8::MAX as i64 || inner < std::i8::MIN as i64 {
                                    return Err(VmError::Overflow);
                                }
                            
                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        Some(Instruction::i64Load8Unsigned) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I64(inner) = value {
                                if inner > std::u8::MAX as i64 || inner < std::u8::MIN as i64 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        Some(Instruction::i64Load16Signed) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I64(inner) = value {
                                if inner > std::i16::MAX as i64 || inner < std::i16::MIN as i64 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        Some(Instruction::i64Load16Unsigned) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I64(inner) = value {
                                if inner > std::u16::MAX as i64 || inner < std::u16::MIN as i64 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        Some(Instruction::i64Load32Signed) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I64(inner) = value {
                                if inner > std::i32::MAX as i64 || inner < std::i32::MIN as i64 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        Some(Instruction::i64Load32Unsigned) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::I64(inner) = value {
                                if inner > std::u32::MAX as i64 || inner < std::u32::MIN as i64 {
                                    return Err(VmError::Overflow);
                                }

                                argv.push(value);
                            } else {
                                panic!("Popped value that is not i64!");
                            }
                        },
                        Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                        _        => panic!("Cannot fetch from memory! Invalid instruction!")
                    }
                } else {
                    let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                    let mut cursor = Cursor::new(&bytes);
                    let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                    argv.push(VmValue::I64(val));
                }
            }
            VmType::F32 => {
                let byte = fun.fetch(ip.ip);

                // Fetch value from memory
                if let ArgLocation::Memory = al {
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
                        Some(Instruction::f32Load) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::F32(_) = value {
                                argv.push(value);
                            } else {
                                panic!("Popped value that is not f32!");
                            }
                        },
                        Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                        _        => panic!("Cannot fetch from memory! Invalid instruction!")
                    }
                } else {
                    let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                    let mut cursor = Cursor::new(&bytes);
                    let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                    argv.push(VmValue::F32(val));
                }
            }
            VmType::F64 => {
                let byte = fun.fetch(ip.ip);

                // Fetch value from memory
                if let ArgLocation::Memory = al {
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
                        Some(Instruction::f64Load) => {
                            // Fetch coordinates
                            ip.increment();
                            let x = fun.fetch(ip.ip) as usize;
                            ip.increment();
                            let y = fun.fetch(ip.ip) as usize;

                            let value = heap[x][y].unwrap();
                            heap[x][y] = None;

                            if let VmValue::F64(_) = value {
                                argv.push(value);
                            } else {
                                panic!("Popped value that is not f64!");
                            }
                        },
                        Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                        _        => panic!("Cannot fetch from memory! Invalid instruction!")
                    }
                } else {
                    let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                    let mut cursor = Cursor::new(&bytes);
                    let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                    argv.push(VmValue::F64(val));
                }
            }
            VmType::i32Array2 => {
                let mut result: [i32; 2] = [0; 2];
                let mut buffer: Vec<i32> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::i32Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load8Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::i8::MAX as i32 || inner < std::i8::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }
                                
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load8Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::u8::MAX as i32 || inner < std::u8::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load16Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::i16::MAX as i32 || inner < std::i16::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load16Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::u16::MAX as i32 || inner < std::u16::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                        argv.push(VmValue::I32(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i32Array2(result));
            }
            VmType::i32Array4 => {
                let mut result: [i32; 4] = [0; 4];
                let mut buffer: Vec<i32> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::i32Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load8Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::i8::MAX as i32 || inner < std::i8::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }
                                
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load8Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::u8::MAX as i32 || inner < std::u8::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load16Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::i16::MAX as i32 || inner < std::i16::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load16Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::u16::MAX as i32 || inner < std::u16::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                        argv.push(VmValue::I32(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i32Array4(result));
            }
            VmType::i32Array8 => {
                let mut result: [i32; 8] = [0; 8];
                let mut buffer: Vec<i32> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::i32Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load8Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::i8::MAX as i32 || inner < std::i8::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }
                                
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load8Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::u8::MAX as i32 || inner < std::u8::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load16Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::i16::MAX as i32 || inner < std::i16::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(Instruction::i32Load16Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I32(inner) = value {
                                    if inner > std::u16::MAX as i32 || inner < std::u16::MIN as i32 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i32!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i32 = cursor.read_i32::<BigEndian>().unwrap();

                        argv.push(VmValue::I32(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i32Array8(result));
            }
            VmType::i64Array2 => {
                let mut result: [i64; 2] = [0; 2];
                let mut buffer: Vec<i64> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::i64Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load8Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i8::MAX as i64 || inner < std::i8::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }
                                
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load8Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u8::MAX as i64 || inner < std::u8::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load16Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i16::MAX as i64 || inner < std::i16::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load16Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u16::MAX as i64 || inner < std::u16::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load32Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i32::MAX as i64 || inner < std::i32::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load32Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u32::MAX as i64 || inner < std::u32::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                        argv.push(VmValue::I64(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i64Array2(result));
            }
            VmType::i64Array4 => {
                let mut result: [i64; 4] = [0; 4];
                let mut buffer: Vec<i64> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::i64Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load8Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i8::MAX as i64 || inner < std::i8::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }
                                
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load8Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u8::MAX as i64 || inner < std::u8::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load16Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i16::MAX as i64 || inner < std::i16::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load16Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u16::MAX as i64 || inner < std::u16::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load32Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i32::MAX as i64 || inner < std::i32::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load32Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u32::MAX as i64 || inner < std::u32::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                        argv.push(VmValue::I64(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i64Array4(result));
            }
            VmType::i64Array8 => {
                let mut result: [i64; 8] = [0; 8];
                let mut buffer: Vec<i64> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::i64Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load8Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i8::MAX as i64 || inner < std::i8::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }
                                
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load8Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u8::MAX as i64 || inner < std::u8::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load16Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i16::MAX as i64 || inner < std::i16::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load16Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u16::MAX as i64 || inner < std::u16::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load32Signed) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::i32::MAX as i64 || inner < std::i32::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(Instruction::i64Load32Unsigned) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::I64(inner) = value {
                                    if inner > std::u32::MAX as i64 || inner < std::u32::MIN as i64 {
                                        return Err(VmError::Overflow);
                                    }

                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not i64!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: i64 = cursor.read_i64::<BigEndian>().unwrap();

                        argv.push(VmValue::I64(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::i64Array8(result));
            }
            VmType::f32Array2 => {
                let mut result: [f32; 2] = [0.0; 2];
                let mut buffer: Vec<f32> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::f32Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::F32(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not f32!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                        argv.push(VmValue::F32(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f32Array2(result));
            }
            VmType::f32Array4 => {
                let mut result: [f32; 4] = [0.0; 4];
                let mut buffer: Vec<f32> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::f32Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::F32(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not f32!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                        argv.push(VmValue::F32(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f32Array4(result));
            }
            VmType::f32Array8 => {
                let mut result: [f32; 8] = [0.0; 8];
                let mut buffer: Vec<f32> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::f32Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::F32(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not f32!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(4, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f32 = cursor.read_f32::<BigEndian>().unwrap();

                        argv.push(VmValue::F32(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f32Array8(result));
            }
            VmType::f64Array2 => {
                let mut result: [f64; 2] = [0.0; 2];
                let mut buffer: Vec<f64> = Vec::with_capacity(2);

                // Fetch array elems
                for _ in 0..2 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::f64Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::F64(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not f64!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                        argv.push(VmValue::F64(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f64Array2(result));
            }
            VmType::f64Array4 => {
                let mut result: [f64; 4] = [0.0; 4];
                let mut buffer: Vec<f64> = Vec::with_capacity(4);

                // Fetch array elems
                for _ in 0..4 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::f64Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::F64(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not f64!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                        argv.push(VmValue::F64(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f64Array4(result));
            }
            VmType::f64Array8 => {
                let mut result: [f64; 8] = [0.0; 8];
                let mut buffer: Vec<f64> = Vec::with_capacity(8);

                // Fetch array elems
                for _ in 0..8 {
                    let byte = fun.fetch(ip.ip);

                    // Fetch value from memory
                    if let ArgLocation::Memory = al {
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
                            Some(Instruction::f64Load) => {
                                // Fetch coordinates
                                ip.increment();
                                let x = fun.fetch(ip.ip) as usize;
                                ip.increment();
                                let y = fun.fetch(ip.ip) as usize;

                                let value = heap[x][y].unwrap();
                                heap[x][y] = None;

                                if let VmValue::F64(_) = value {
                                    argv.push(value);
                                } else {
                                    panic!("Popped value that is not f64!");
                                }
                            },
                            Some(op) => panic!(format!("Cannot fetch from memory! Invalid instruction! Expected `PopLocal` or `PopOperand` or a load instruction! Got: `{:?}` ", op)),
                            _        => panic!("Cannot fetch from memory! Invalid instruction!")
                        }
                    } else {
                        let bytes: Vec<u8> = fetch_bytes(8, ip, fun);
                        let mut cursor = Cursor::new(&bytes);
                        let val: f64 = cursor.read_f64::<BigEndian>().unwrap();

                        argv.push(VmValue::F64(val));
                    }
                }

                // Push argument
                result.copy_from_slice(&buffer);
                argv.push(VmValue::f64Array8(result));
            }
            op => {
                panic!(format!(
                    "Invalid argument type in begin block! Received: {:?}",
                    op
                ));
            }
        }
    }

    let argv_types = argv_types.iter().map(|t| t.0).collect();

    Ok((argv_types, argv))
}

fn perform_comparison(op: Instruction, operands: Vec<VmValue>) -> Result<bool, VmError> {
    let op_len = operands.len();
    match op {
        Instruction::Eqz => {
            if op_len != 1 {
                panic!(format!(
                    "Can only perform equality to zero on 1 operand! Got: {}",
                    op_len
                ));
            }

            Ok(compare_to_zero(operands[0]))
        }
        Instruction::Eq => {
            if op_len < 2 {
                panic!(format!(
                    "Cannot perform equality on less than 2 operands! Got: {}",
                    op_len
                ));
            }

            let (result, _) = operands.iter().fold((true, None), |(result, last), op| {
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

            Ok(result)
        }
        Instruction::Ne => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform not equal on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            Ok(operands[0] != operands[1])
        }
        Instruction::LtSigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform less than signed on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            Ok(operands[0].lt(&operands[1]))
        }
        Instruction::LtUnsigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform less than unsigned on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            if !operands[0].is_positive() || !operands[1].is_positive() {
                return Err(VmError::UnsignedOperationSignedOperand);
            }

            Ok(operands[0].lt(&operands[1]))
        }
        Instruction::GtSigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform greather than signed on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            Ok(operands[0].gt(&operands[1]))
        }
        Instruction::GtUnsigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform greather than unsigned on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            if !operands[0].is_positive() || !operands[1].is_positive() {
                return Err(VmError::UnsignedOperationSignedOperand);
            }

            Ok(operands[0].gt(&operands[1]))
        }
        Instruction::LeSigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform less or equal signed on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            Ok(operands[0].le(&operands[1]))
        }
        Instruction::LeUnsigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform less or equal unsigned on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            if !operands[0].is_positive() || !operands[1].is_positive() {
                return Err(VmError::UnsignedOperationSignedOperand);
            }

            Ok(operands[0].le(&operands[1]))
        }
        Instruction::GeSigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform greather or equal signed on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            Ok(operands[0].ge(&operands[1]))
        }
        Instruction::GeUnsigned => {
            if op_len != 2 {
                panic!(format!(
                    "Cannot perform greather or equal unsigned on more or less than 2 operands! Got: {}",
                    op_len
                ));
            }

            if !operands[0].is_positive() || !operands[1].is_positive() {
                return Err(VmError::UnsignedOperationSignedOperand);
            }

            Ok(operands[0].ge(&operands[1]))
        }
        _ => unimplemented!(),
    }
}

fn compare_to_zero(operand: VmValue) -> bool {
    match operand {
        VmValue::I32(val) => val == 0,
        VmValue::I64(val) => val == 0,
        VmValue::F32(val) => val == 0.0,
        VmValue::F64(val) => val == 0.0,
        VmValue::i32Array2(val) => val.iter().all(|v| *v == 0),
        VmValue::i32Array4(val) => val.iter().all(|v| *v == 0),
        VmValue::i32Array8(val) => val.iter().all(|v| *v == 0),
        VmValue::i64Array2(val) => val.iter().all(|v| *v == 0),
        VmValue::i64Array4(val) => val.iter().all(|v| *v == 0),
        VmValue::i64Array8(val) => val.iter().all(|v| *v == 0),
        VmValue::f32Array2(val) => val.iter().all(|v| *v == 0.0),
        VmValue::f32Array4(val) => val.iter().all(|v| *v == 0.0),
        VmValue::f32Array8(val) => val.iter().all(|v| *v == 0.0),
        VmValue::f64Array2(val) => val.iter().all(|v| *v == 0.0),
        VmValue::f64Array4(val) => val.iter().all(|v| *v == 0.0),
        VmValue::f64Array8(val) => val.iter().all(|v| *v == 0.0),
        _ => panic!("Operand type not supported for comparison"),
    }
}

fn perform_addition(op: Instruction, operand_stack: &mut Stack<VmValue>) -> Result<(), VmError> {
    let len = operand_stack.len();

    if len < 2 {
        panic!(format!(
            "Cannot perform addition on less than 2 operands! Got: {}",
            len
        ));
    }

    match op {
        Instruction::Add => {
            let mut buf: Vec<VmValue> = Vec::with_capacity(len);

            // Move items from operand stack to buffer
            for _ in 0..len {
                buf.push(operand_stack.pop());
            }

            // Perform addition
            let mut acc: VmValue = buf[0];
            for i in 1..buf.len() {
                acc = match acc + buf[i] {
                    Ok(res) => res,
                    Err(err) => return Err(err),
                }
            }

            // Push result back to operand stack
            operand_stack.push(acc);
        }
        _ => panic!(format!(
            "Must receive an addition instruction! Got: {:?}",
            op
        )),
    };

    Ok(())
}

fn perform_substraction(
    op: Instruction,
    operand_stack: &mut Stack<VmValue>,
) -> Result<(), VmError> {
    let len = operand_stack.len();

    if len != 2 {
        panic!(format!("Cannot perform substraction on {} operands!", len));
    }

    match op {
        Instruction::Sub => {
            // Perform substraction
            let to_substract = operand_stack.pop(); // last inserted
            let mut result = operand_stack.pop(); // first inserted

            result = match result - to_substract {
                Ok(res) => res,
                Err(err) => return Err(err),
            };

            // Push result back to operand stack
            operand_stack.push(result);
        }
        _ => panic!(format!(
            "Must receive a substraction instruction! Got: {:?}",
            op
        )),
    };

    Ok(())
}

fn perform_multiplication(
    op: Instruction,
    operand_stack: &mut Stack<VmValue>,
) -> Result<(), VmError> {
    let len = operand_stack.len();

    if len < 2 {
        panic!(format!(
            "Cannot perform multiplication on less than 2 operands! Got: {}",
            len
        ));
    }

    match op {
        Instruction::Mul => {
            let mut buf: Vec<VmValue> = Vec::with_capacity(len);

            // Move items from operand stack to buffer
            for _ in 0..len {
                buf.push(operand_stack.pop());
            }

            // Perform multiplication
            let mut result: VmValue = buf[0];
            for i in 1..buf.len() {
                result = match result * buf[i] {
                    Ok(res) => res,
                    Err(err) => return Err(err),
                }
            }

            // Push result back to operand stack
            operand_stack.push(result);
        }
        _ => panic!(format!(
            "Must receive an multiplication instruction! Got: {:?}",
            op
        )),
    };

    Ok(())
}

fn perform_div_signed(op: Instruction, operand_stack: &mut Stack<VmValue>) -> Result<(), VmError> {
    let len = operand_stack.len();

    if len != 2 {
        panic!(format!(
            "Cannot perform signed division on {} operands! Must be 2!",
            len
        ));
    }

    match op {
        Instruction::DivSigned => {
            // Perform signed division
            let divider = operand_stack.pop();
            let mut result = operand_stack.pop();

            result = match result / divider {
                Ok(res) => res,
                Err(err) => return Err(err),
            };

            // Push result back to operand stack
            operand_stack.push(result);
        }
        _ => panic!(format!(
            "Must receive an signed division instruction! Got: {:?}",
            op
        )),
    };

    Ok(())
}

fn perform_div_unsigned(
    op: Instruction,
    operand_stack: &mut Stack<VmValue>,
) -> Result<(), VmError> {
    let len = operand_stack.len();

    if len != 2 {
        panic!(format!(
            "Cannot perform unsigned division on {} operands! Must be 2!",
            len
        ));
    }

    match op {
        Instruction::DivUnsigned => {
            // Perform unsigned division
            let divider = operand_stack.pop();
            let mut result = operand_stack.pop();

            if !divider.is_positive() || !result.is_positive() {
                return Err(VmError::UnsignedOperationSignedOperand);
            }

            result = match result / divider {
                Ok(res) => res,
                Err(err) => return Err(err),
            };

            // Push result back to operand stack
            operand_stack.push(result);
        }
        _ => panic!(format!(
            "Must receive an unsigned division instruction! Got: {:?}",
            op
        )),
    };

    Ok(())
}
fn perform_rem_signed(op: Instruction, operand_stack: &mut Stack<VmValue>) -> Result<(), VmError> {
    let len = operand_stack.len();

    if len != 2 {
        panic!(format!(
            "Cannot perform signed remainder instruction on {} operands! Must be 2!",
            len
        ));
    }

    match op {
        Instruction::RemSigned => {
            // Perform signed remainder
            let to_divide = operand_stack.pop();
            let mut result = operand_stack.pop();

            result = match result % to_divide {
                Ok(res) => res,
                Err(err) => return Err(err),
            };

            // Push result back to operand stack
            operand_stack.push(result);
        }
        _ => panic!(format!(
            "Must receive signed remainder instruction! Got: {:?}",
            op
        )),
    };

    Ok(())
}
fn perform_rem_unsigned(
    op: Instruction,
    operand_stack: &mut Stack<VmValue>,
) -> Result<(), VmError> {
    let len = operand_stack.len();

    if len != 2 {
        panic!(format!(
            "Cannot perform unsigned remainder instruction on {} operands! Must be 2!",
            len
        ));
    }

    match op {
        Instruction::RemUnsigned => {
            // Perform unsigned remainder
            let to_divide = operand_stack.pop();
            let mut result = operand_stack.pop();

            if !to_divide.is_positive() || !result.is_positive() {
                return Err(VmError::UnsignedOperationSignedOperand);
            }

            result = match result % to_divide {
                Ok(res) => res,
                Err(err) => return Err(err),
            };

            // Push result back to operand stack
            operand_stack.push(result);
        }
        _ => panic!(format!(
            "Must receive unsigned remainder instruction! Got: {:?}",
            op
        )),
    };

    Ok(())
}

fn perform_min(op: Instruction, operand_stack: &mut Stack<VmValue>) {
    let len = operand_stack.len();

    if len < 1 {
        panic!(format!("Cannot perform min on 0 operands"));
    }

    match op {
        Instruction::Min => {
            let mut buf: Vec<VmValue> = Vec::with_capacity(len);

            // Move items from operand stack to buffer
            for _ in 0..len {
                buf.push(operand_stack.pop());
            }

            // Perform min
            let mut result = buf[0];
            for x in buf.iter() {
                if x.lt(&result) {
                    result = *x;
                }
            }

            operand_stack.push(result);
        }
        _ => panic!(format!("Must receive a min instruction! Got: {:?}", op)),
    };
}

fn perform_max(op: Instruction, operand_stack: &mut Stack<VmValue>) {
    let len = operand_stack.len();

    if len < 1 {
        panic!(format!("Cannot perform max on 0 operands"));
    }

    match op {
        Instruction::Max => {
            let mut buf: Vec<VmValue> = Vec::with_capacity(len);

            // Move items from operand stack to buffer
            for _ in 0..len {
                buf.push(operand_stack.pop());
            }

            // Perform max
            let mut result = buf[0];
            for x in buf.iter() {
                if x.gt(&result) {
                    result = *x;
                }
            }

            operand_stack.push(result);
        }
        _ => panic!(format!("Must receive a max instruction! Got: {:?}", op)),
    };
}

fn perform_float_common(op: Instruction, operand_stack: &mut Stack<VmValue>) -> Result<(), VmError> {
    let len = operand_stack.len();

    let mut buf: Vec<VmValue> = Vec::with_capacity(len);
    match op{
        Instruction::Abs => {
            if len < 1 {
                panic!("Cannot perform Abs on less than 1 operand")
            }
            for _ in 0..len {
                let value = operand_stack.pop();
                if !is_type_float(value) {
                    return Err(VmError::InvalidOperator);
                }
                match value.abs() {
                    Ok(val) => buf.push(val),
                    Err(err) => return Err(err)
                }
            }
        }
        Instruction::Neg => {
            if len < 1 {
                panic!("Cannot perform Neg on less than 1 operand")
            }
            for _ in 0..len {
                let value = operand_stack.pop();
                if !is_type_float(value) {
                    return Err(VmError::InvalidOperator);
                }
                match -value {
                    Ok(val) => buf.push(val),
                    Err(err) => return Err(err)
                }
            }
        }
        Instruction::Div => {
            if len != 2 {
                panic!(format!("Can perform Div only on 2 operands. Got {:?}", len))
            }

            let to_divide = operand_stack.pop();
            let mut result = operand_stack.pop();

            if !is_type_float(to_divide) || !is_type_float(result){
                return Err(VmError::InvalidOperator)
            }

            result = match result / to_divide {
                Ok(res) => res,
                Err(err) => return Err(err)
            };

            operand_stack.push(result);
            // Return
            return Ok(());
        }
        Instruction::Ceil => {
            if len < 1 {
                panic!("Cannot perform Ceil on less than 1 operand")
            }
            for _ in 0..len {
                let value = operand_stack.pop();
                if !is_type_float(value) {
                    return Err(VmError::InvalidOperator);
                }
                match value.ceil() {
                    Ok(val) => buf.push(val),
                    Err(err) => return Err(err)
                }
            }
        }
        Instruction::Floor => {
            if len < 1 {
                panic!("Cannot perform Floor on less than 1 operand")
            }
            for _ in 0..len {
                let value = operand_stack.pop();
                if !is_type_float(value) {
                    return Err(VmError::InvalidOperator);
                }
                match value.floor() {
                    Ok(val) => buf.push(val),
                    Err(err) => return Err(err)
                }
            }
        }
        Instruction::Trunc => {
            if len < 1 {
                panic!("Cannot perform Trunc on less than 1 operand")
            }
            for _ in 0..len {
                let value = operand_stack.pop();
                if !is_type_float(value) {
                    return Err(VmError::InvalidOperator);
                }
                match value.trunc() {
                    Ok(val) => buf.push(val),
                    Err(err) => return Err(err)
                }
            }
        }
        Instruction::Nearest => {
            if len < 1 {
                panic!("Cannot perform Nearest on less than 1 operand")
            }
            for _ in 0..len {
                let value = operand_stack.pop();
                if !is_type_float(value) {
                    return Err(VmError::InvalidOperator);
                }
                match value.round() {
                    Ok(val) => buf.push(val),
                    Err(err) => return Err(err)
                }
            }
        }
        Instruction::CopySign => {
            if len != 2 {
                panic!(format!("Can perform CopySign only on 2 operands. Got {:?}", len))
            }
            let to_copy = operand_stack.pop();
            let mut result = operand_stack.pop();

            if !is_type_float(to_copy) || !is_type_float(result) {
                return Err(VmError::InvalidOperator);
            }
            
            result = match result.copysign(&to_copy) {
                Ok(res) => res,
                Err(err) => return Err(err)
            };

            operand_stack.push(result);
            // Return
            return Ok(());
        }
        Instruction::Sqrt => {
            if len < 1 {
                panic!("Cannot perform Sqrt on less than 1 operand")
            }
            for _ in 0..len {
                let value = operand_stack.pop();
                if !is_type_float(value) {
                    return Err(VmError::InvalidOperator);
                }
                match value.sqrt() {
                    Ok(val) => buf.push(val),
                    Err(err) => return Err(err)
                }
            }
        }
        _ => panic!(format!("Must receive a float only common operation. Got {:?}", op))
    }

    // Finally, push the results to operand stack
    while let Some(v) = buf.pop(){
        operand_stack.push(v);
    }

    Ok(())
}

fn is_type_float(operand: VmValue) -> bool {
    match operand{
        VmValue::F32(_) | VmValue::F64(_) | 
        VmValue::f32Array2(_) | VmValue::f32Array4(_) | VmValue::f32Array8(_) | VmValue::f32Array16(_) | 
        VmValue::f32Array32(_) | VmValue::f32Array64(_) | VmValue::f32Array128(_) | VmValue::f32Array256(_) |
        VmValue::f64Array2(_) | VmValue::f64Array4(_) | VmValue::f64Array8(_) | VmValue::f64Array16(_) |  
        VmValue::f64Array32(_) | VmValue::f64Array64(_) | VmValue::f64Array128(_) | VmValue::f64Array256(_) => return true,
        _ =>return false
    }
}

fn is_type_integer(operand: VmValue) -> bool {
    !is_type_float(operand)
}  

fn perform_integer_common(op: Instruction, operand_stack: &mut Stack<VmValue>) -> Result<(), VmError> {
    let len = operand_stack.len();
    
    if len != 2 {
        panic!(format!("Can perform {:?} only on 2 operands. Got {:?}", op, len))
    }

    let second = operand_stack.pop();
    let first = operand_stack.pop();
    let result;

    if !is_type_integer(first) || !is_type_integer(second) {
        return Err(VmError::InvalidOperator);
    }

    match op{
        Instruction::And => {
            result = match first & second{
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        Instruction::Or => {
            result = match first | second{
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        Instruction::Xor => {
            result = match first ^ second{
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        Instruction::Shl => {
            result = match first << second{
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        Instruction::ShrSigned => {
            result = match first >> second{
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        Instruction::ShrUnsigned => {
            if !first.is_positive() || !second.is_positive(){
                return Err(VmError::UnsignedOperationSignedOperand);
            }

            result = match first >> second{
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        Instruction::Rotl => {
            result = match first.rotate_left(&second){
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        Instruction::Rotr => {
            result = match first.rotate_right(&second){
                Ok(res) => res,
                Err(err) => return Err(err)
            };
        }
        _ => panic!(format!("Must receive a integer only common operation. Got {:?}", op))
    }

    operand_stack.push(result);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Hash;

    #[test]
    #[rustfmt::skip]
    #[should_panic(expected = "first instruction cannot be a Loop instruction")]
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
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap()).unwrap();
    }

    #[test]
    #[rustfmt::skip]
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
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap()).unwrap();
    }

    #[test]
    #[rustfmt::skip]
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
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap()).unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_executes_correctly_with_loops() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
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
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Loop.repr(),
            0x05,                            // 5 arity. The latest 5 items on the caller stack will be pushed to the new frame
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
            Instruction::BreakIf.repr(),     // Break if items on the operand stack are equal  
            Instruction::Eq.repr(),
            Instruction::PopOperand.repr(),
            Instruction::PushOperand.repr(), // Increment counter
            0x01,
            0x00,
            Instruction::i32Const.repr(),
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
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap()).unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_breaks_loops_from_nested_scopes1() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
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
            Instruction::If.repr(),          // Break if items on the operand stack are equal  
            0x00,                            // Arity 0
            Instruction::Eq.repr(),
            Instruction::Break.repr(),       // Break loop
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
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
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap()).unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_breaks_loops_from_nested_scopes2() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
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
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Loop.repr(),
            0x05,                            // 5 arity. The latest 5 items on the caller stack will be pushed to the new frame
            Instruction::PickLocal.repr(),
            0x00,
            0x04,
            Instruction::Begin.repr(),
            0x01,
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
            Instruction::BreakIf.repr(),     // Break if items on the operand stack are equal  
            Instruction::Eq.repr(),
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
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap()).unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_works_with_if_else_arguments() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
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
            0x00, // f32 value
            0x00,
            0x00,
            0x5f,
            Instruction::PickLocal.repr(),   // Dupe elems on stack 11 times (usize is 16bits)
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
            bitmask, // Reference bits
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::PushLocal.repr(),  // Move counter from operand stack back to call stack
            0x01,
            bitmask,                        // Reference bits
            Instruction::i32Const.repr(),
            Instruction::PopOperand.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr(),
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![],
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![],
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
            .unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_executes_correctly_with_calls_and_returns() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
        let mut bitmask: u8 = 0;

        bitmask.set(0, true);

        let main_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                               // 0 Arity
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
            0x00,                               // Fun idx (16 bits)
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x00,
            Instruction::PushOperand.repr(),
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            0x00,                               // Loop 4 times
            0x00,
            0x00,
            0x04,
            Instruction::BreakIf.repr(),
            Instruction::Eq.repr(),
            Instruction::End.repr(),
            Instruction::End.repr(),
        ];

        let increment_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                               // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),    // Increment given arg by 1
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
            Instruction::PushLocal.repr(),
            0x01,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::PopOperand.repr(),
            Instruction::Return.repr(),
            0x01,
            Instruction::End.repr(),
        ];

        let f1 = Function {
            arity: 0,
            name: "debug_test1".to_owned(),
            block: main_block,
            return_type: None,
            arguments: vec![],
        };

        let f2 = Function {
            arity: 1,
            name: "debug_test2".to_owned(),
            block: increment_block,
            return_type: Some(VmType::I32),
            arguments: vec![VmType::I32],
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![f1, f2],
            imports: vec![],
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
            .unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_executes_correctly_with_return_from_nested_block() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
        let mut bitmask: u8 = 0;

        bitmask.set(0, true);

        let main_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                                // 0 Arity
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
            0x00,                               // Fun idx (16 bits)
            0x01,
            Instruction::PickLocal.repr(),
            0x00,
            0x00,
            Instruction::PushOperand.repr(),
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            0x00,                              // Loop 4 times
            0x00,
            0x00,
            0x04,
            Instruction::BreakIf.repr(),
            Instruction::Eq.repr(),
            Instruction::End.repr(),
            Instruction::End.repr(),
        ];

        let increment_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00, // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),   // Increment given arg by 1
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
            Instruction::PushLocal.repr(),
            0x01,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::PopOperand.repr(),
            Instruction::Begin.repr(),
            0x01,
            Instruction::Return.repr(),
            0x01,
            Instruction::End.repr(),
            Instruction::End.repr(),
        ];

        let f1 = Function {
            arity: 0,
            name: "debug_test1".to_owned(),
            block: main_block,
            return_type: None,
            arguments: vec![],
        };

        let f2 = Function {
            arity: 1,
            name: "debug_test2".to_owned(),
            block: increment_block,
            return_type: Some(VmType::I32),
            arguments: vec![VmType::I32],
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![f1, f2],
            imports: vec![],
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
            .unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_executes_correctly_with_loading_heap_value_set_from_fun_call() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
        let mut bitmask: u8 = 0;

        bitmask.set(0, true);

        let main_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                                 // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::i32Store.repr(),
            0x00,
            0x00,
            Instruction::Loop.repr(),
            0x00,
            Instruction::Call.repr(),
            0x00,                                // Fun idx (16 bits)
            0x01,
            Instruction::PushLocal.repr(),
            0x01,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Load.repr(),         // Load element at x, y = 0x00, 0x00
            0x00,
            0x00,
            Instruction::PickLocal.repr(),
            0x00,
            0x00,
            Instruction::PushOperand.repr(),
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            0x00,                                // Loop 4 times
            0x00,
            0x00,
            0x04,
            Instruction::BreakIf.repr(),
            Instruction::Eq.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            Instruction::i32Store.repr(),
            0x00,
            0x00,
            Instruction::End.repr(),
            Instruction::End.repr(),
        ];

        let increment_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                               // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),    // Increment given arg by 1
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Load.repr(),        // Load element at x, y = 0x00, 0x00
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::i32Store.repr(),        // Store result to heap at x, y = 0x00, 0x00
            0x00,
            0x00,
            Instruction::Return.repr(),
            0x00,
            Instruction::End.repr(),
        ];

        let f1 = Function {
            arity: 0,
            name: "debug_test1".to_owned(),
            block: main_block,
            return_type: None,
            arguments: vec![],
        };

        let f2 = Function {
            arity: 0,
            name: "debug_test2".to_owned(),
            block: increment_block,
            return_type: None,
            arguments: vec![],
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![f1, f2],
            imports: vec![],
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
            .unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_executes_correctly_with_lower_sized_integer_interpretations() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);
        let mut bitmask: u8 = 0;

        bitmask.set(0, true);

        let main_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                                          // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::i32Store8.repr(),
            0x00,
            0x00,
            Instruction::Loop.repr(),
            0x00,
            Instruction::Call.repr(),
            0x00,                                         // Fun idx (16 bits)
            0x01,
            Instruction::PushLocal.repr(),
            0x01,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Load8Unsigned.repr(),         // Load element at x, y = 0x00, 0x00
            0x00,
            0x00,
            Instruction::PickLocal.repr(),
            0x00,
            0x00,
            Instruction::PushOperand.repr(),
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            0x00,                                        // Loop 4 times
            0x00,   
            0x00,
            0x04,
            Instruction::BreakIf.repr(),
            Instruction::Eq.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::PopLocal.repr(),
            Instruction::i32Store8.repr(),
            0x00,
            0x00,
            Instruction::End.repr(),
            Instruction::End.repr(),
        ];

        let increment_block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                                      // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),           // Increment given arg by 1
            0x02,
            bitmask,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Load8Unsigned.repr(),               // Load element at x, y = 0x00, 0x00
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::i32Store8.repr(),             // Store result to heap at x, y = 0x00, 0x00
            0x00,
            0x00,
            Instruction::Return.repr(),
            0x00,
            Instruction::End.repr(),
        ];

        let f1 = Function {
            arity: 0,
            name: "debug_test1".to_owned(),
            block: main_block,
            return_type: None,
            arguments: vec![],
        };

        let f2 = Function {
            arity: 0,
            name: "debug_test2".to_owned(),
            block: increment_block,
            return_type: None,
            arguments: vec![],
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![f1, f2],
            imports: vec![],
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
            .unwrap();

        assert!(true);
    }

    #[test]
    #[rustfmt::skip]
    fn it_returns_correctly_on_overflow_1() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x07,
            0xff,
            0xff,
            0xff,
            Instruction::i32Store8.repr(),
            0x00,
            0x00,
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        let result = vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap());

        assert_eq!(result, Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_returns_correctly_on_overflow_2() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x07,
            0xff,
            0xff,
            0xff,
            Instruction::i32Store16.repr(),
            0x00,
            0x00,
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        let result = vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap());

        assert_eq!(result, Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_returns_correctly_on_overflow_3() {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x07,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            Instruction::i64Store32.repr(),
            0x00,
            0x00,
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![]
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![]
        };

        vm.load(module).unwrap();
        let result = vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap());

        assert_eq!(result, Err(VmError::Overflow));
    }

    // Helper function to run code blocks
    fn execute_vm_code_common(block: Vec<u8>) -> Result<Gas, VmError> {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![],
        };

        let module = Module {
            module_hash: Hash::NULL_RLP,
            functions: vec![function],
            imports: vec![],
        };

        vm.load(module).unwrap();
        vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_addition_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x0b,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_addition_reaches_max_value_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x7f,                             // i32 MAX - 1
            0xff,
            0xff,
            0xfe,
            0x00,                             // 1
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x7f,
            0xff,
            0xff,
            0xff,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_addition_high_limit_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x7f,                             // i32 MAX
            0xff,
            0xff,
            0xff,
            0x00,                             // 1
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];
        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_addition_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x0b,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_addition_reaches_max_value_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x7f,                             // i64 MAX - 1
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xfe,
            0x00,                             // 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x7f,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_addition_high_limit_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x7f,                             // i64 MAX
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x00,                              // 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Add.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];
        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_addition_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x3f,                             // 0.5
            0x00,
            0x00,
            0x00,
            0x41,                             // 9.5
            0x18,
            0x00,
            0x00,
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x41,                             // 10
            0x20,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_addition_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f64Const.repr(),
            Instruction::f64Const.repr(),
            0x0f,                             // 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012481292144422623
            0xff,
            0x00,
            0xff,
            0x00,
            0x00,
            0x00,
            0x00,
            0x0f,                             // 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012481187717534078
            0xff,
            0x00,
            0xee,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x10,                             // 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024962479861956702
            0x0f,
            0x00,
            0xf6,
            0x80,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_substraction_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x0b,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Sub.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x0a,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_substraction_reaches_min_value_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x80,                             // i32 MIN + 1
            0x00,
            0x00,
            0x01,
            0x00,                             // 1
            0x00,
            0x00,
            0x01,
            Instruction::Sub.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x80,                             // i32 MIN
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_substraction_lower_limit_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x80,                             // i32 MIN
            0x00,
            0x00,
            0x00,
            0x00,                             // 1
            0x00,
            0x00,
            0x01,
            Instruction::Sub.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];
        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow))
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_substraction_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x0b,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Sub.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x0a,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_substraction_reaches_min_value_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x80,                             // i64 MIN + 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,                             // 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Sub.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x80,                             // i64 MIN
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_substraction_lower_limit_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x80,                             // i64 MIN
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,                              // 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Sub.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];
        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_substraction_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x41,                             // 10.5
            0x28,
            0x00,
            0x00,
            0x3f,                             // 0.5
            0x00,
            0x00,
            0x00,
            Instruction::Sub.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x41,                             // 10
            0x20,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_substraction_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f64Const.repr(),
            Instruction::f64Const.repr(),
            0x0f,                             // 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012481292144422623
            0xff,
            0x00,
            0xff,
            0x00,
            0x00,
            0x00,
            0x00,
            0x0f,                             // 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012481187717534078
            0xff,
            0x00,
            0xee,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Sub.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x0e,                             // 0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010442688854518057
            0xf1,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_multiplication_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x05,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x0a,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_multiplication_on_multiple_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x04,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x05,
            0x00,
            0x00,
            0x00,
            0x05,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x64,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_multiplication_higher_limit_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x7f,
            0xff,
            0xff,
            0xff,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::Mul.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_multiplication_lower_limit_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::Mul.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_multiplication_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x05,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x0a,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_multiplication_higher_limit_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x7f,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::Mul.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_overflows_multiplication_lower_limit_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::Mul.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_multiplication_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x3f,                             // 1.5
            0xc0,
            0x00,
            0x00,
            0x40,                             // 2.5
            0x20,
            0x00,
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 3.75
            0x70,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_multiplication_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f64Const.repr(),
            Instruction::f64Const.repr(),
            0x0f,                             // 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012481292144422623
            0xff,
            0x00,
            0xff,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,                             // 2.0
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x10,                             // 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024962584288845247
            0x0f,
            0x00,
            0xff,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_unsigned_division_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x00,
            0x00,
            0x05,
            Instruction::DivUnsigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_signed_division_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            Instruction::DivSigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 2
            0x00,
            0x00,
            0x02,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_unsigned_division_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x7f,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xfe,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::DivUnsigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x3f,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_signed_division_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x80,                             // ‭-9223372036854775808‬
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xff,                             // -2
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xfe,
            Instruction::DivSigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x40,                             // 4611686018427387904‬
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_unsigned_division_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x40,                             // 4.6
            0x93,
            0x33,
            0x33,
            0x40,                             // 2
            0x00,
            0x00,
            0x00,
            Instruction::DivUnsigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2.3
            0x13,
            0x33,
            0x33,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_signed_division_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0xc0,                             // -4.6
            0x93,
            0x33,
            0x33,
            0xc0,                             // -2
            0x00,
            0x00,
            0x00,
            Instruction::DivSigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2.3
            0x13,
            0x33,
            0x33,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_unsigned_remainder_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x00,
            0x00,
            0x03,
            Instruction::RemUnsigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_signed_remainder_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0xff,                             // -3
            0xff,
            0xff,
            0xfd,
            Instruction::RemSigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -1
            0xff,
            0xff,
            0xff,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_unsigned_remainder_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x11,                             // 1234567897891011123
            0x22,
            0x10,
            0xf6,
            0x4c,
            0xe4,
            0xfa,
            0x33,
            0x00,                             // 2
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::RemUnsigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x00,                             // 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_signed_remainder_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0xee,                             // -1234567897891011123
            0xdd,
            0xef,
            0x09,
            0xb3,
            0x1b,
            0x05,
            0xcd,
            0x00,                             // 2
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            Instruction::RemSigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0xff,                             // -1
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_unsigned_remainder_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x41,                             // 20.5
            0xa4,
            0x00,
            0x00,
            0x40,                             // 2
            0x00,
            0x00,
            0x00,
            Instruction::RemUnsigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x3f,                             // 0.5
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_signed_remainder_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0xc1,                             // -20.5
            0xa4,
            0x00,
            0x00,
            0xc0,                             // -2
            0x00,
            0x00,
            0x00,
            Instruction::RemSigned.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xbf,                             // -0.5
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_min_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x05,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            0x00,                             // 8953
            0x00,
            0x22,
            0xf9,
            0x00,                             // 14920
            0x00,
            0x3a,
            0x48,
            0x00,                             // 4174
            0x00,
            0x10,
            0x4e,
            0x00,                             // 16275
            0x00,
            0x3f,
            0x93,
            Instruction::Min.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 4174
            0x00,
            0x10,
            0x4e,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_min_i32_2() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x07,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            0x00,                             // 8953
            0x00,
            0x22,
            0xf9,
            0xff,                             // -375537
            0xfa,
            0x45,
            0x0f,
            0x00,                             // 14920
            0x00,
            0x3a,
            0x48,
            0x00,                             // 4174
            0x00,
            0x10,
            0x4e,
            0xff,                             // -3755379
            0xc6,
            0xb2,
            0x8d,
            0x00,                             // 16275
            0x00,
            0x3f,
            0x93,
            Instruction::Min.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -3755379
            0xc6,
            0xb2,
            0x8d,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_min_i32_3() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x08,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            0x00,                             // 8953
            0x00,
            0x22,
            0xf9,
            0xff,                             // -375537
            0xfa,
            0x45,
            0x0f,
            0x00,                             // 14920
            0x00,
            0x3a,
            0x48,
            0x00,                             // 4174
            0x00,
            0x10,
            0x4e,
            0x80,                             // -2147483648
            0x00,
            0x00,
            0x00,
            0xff,                             // -3755379
            0xc6,
            0xb2,
            0x8d,
            0x00,                             // 16275
            0x00,
            0x3f,
            0x93,
            Instruction::Min.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x80,                             // -2147483648
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_max_i32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x05,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            0x00,                             // 8953
            0x00,
            0x22,
            0xf9,
            0x00,                             // 14920
            0x00,
            0x3a,
            0x48,
            0x00,                             // 4174
            0x00,
            0x10,
            0x4e,
            0x00,                             // 16275
            0x00,
            0x3f,
            0x93,
            Instruction::Max.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_max_i32_2() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x07,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            0x00,                             // 8953
            0x00,
            0x22,
            0xf9,
            0xff,                             // -375537
            0xfa,
            0x45,
            0x0f,
            0x00,                             // 14920
            0x00,
            0x3a,
            0x48,
            0x00,                             // 4174
            0x00,
            0x10,
            0x4e,
            0xff,                             // -3755379
            0xc6,
            0xb2,
            0x8d,
            0x00,                             // 16275
            0x00,
            0x3f,
            0x93,
            Instruction::Max.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_max_i32_3() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x08,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 20591
            0x00,
            0x50,
            0x6f,
            0x00,                             // 8953
            0x00,
            0x22,
            0xf9,
            0xff,                             // -375537
            0xfa,
            0x45,
            0x0f,
            0x00,                             // 14920
            0x00,
            0x3a,
            0x48,
            0x00,                             // 4174
            0x00,
            0x10,
            0x4e,
            0x7f,                             // 2147483647
            0xff,
            0xff,
            0xff,
            0xff,                             // -3755379
            0xc6,
            0xb2,
            0x8d,
            0x00,                             // 16275
            0x00,
            0x3f,
            0x93,
            Instruction::Max.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x7f,                             // 2147483647
            0xff,
            0xff,
            0xff,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_min_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x03,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x11,                             // ‭1236858285285558588‬   112A 340E ABF1 C93C‬
            0x2a,
            0x34,
            0x0e,
            0xab,
            0xf1,
            0xc9,
            0x3c,
            0x32,                             // ‭3658975365245698789‬   ‭32C7 4AB5 6760 02E5‬
            0xc7,
            0x4a,
            0xb5,
            0x67,
            0x60,
            0x02,
            0xe5,
            0x0f,                             // ‭1111111123658796589‬   ‭F6B 75AE 17AA EE2D‬
            0x6b,
            0x75,
            0xae,
            0x17,
            0xaa,
            0xee,
            0x2d,
            Instruction::Min.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x0f,                             // ‭1111111123658796589‬   ‭F6B 75AE 17AA EE2D‬
            0x6b,
            0x75,
            0xae,
            0x17,
            0xaa,
            0xee,
            0x2d,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_min_i64_2() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x04,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x11,                             // ‭1236858285285558588‬   112A 340E ABF1 C93C‬
            0x2a,
            0x34,
            0x0e,
            0xab,
            0xf1,
            0xc9,
            0x3c,
            0x80,                             // -9223372036854775808
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x32,                             // ‭3658975365245698789‬   ‭32C7 4AB5 6760 02E5‬
            0xc7,
            0x4a,
            0xb5,
            0x67,
            0x60,
            0x02,
            0xe5,
            0x0f,                             // ‭1111111123658796589‬   ‭F6B 75AE 17AA EE2D‬
            0x6b,
            0x75,
            0xae,
            0x17,
            0xaa,
            0xee,
            0x2d,
            Instruction::Min.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x80,                             // -9223372036854775808
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_max_i64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x03,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x11,                             // ‭1236858285285558588‬   112A 340E ABF1 C93C‬
            0x2a,
            0x34,
            0x0e,
            0xab,
            0xf1,
            0xc9,
            0x3c,
            0x32,                             // ‭3658975365245698789‬   ‭32C7 4AB5 6760 02E5‬
            0xc7,
            0x4a,
            0xb5,
            0x67,
            0x60,
            0x02,
            0xe5,
            0x0f,                             // ‭1111111123658796589‬   ‭F6B 75AE 17AA EE2D‬
            0x6b,
            0x75,
            0xae,
            0x17,
            0xaa,
            0xee,
            0x2d,
            Instruction::Max.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x32,                             // ‭3658975365245698789‬   ‭32C7 4AB5 6760 02E5‬
            0xc7,
            0x4a,
            0xb5,
            0x67,
            0x60,
            0x02,
            0xe5,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_max_i64_2() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x04,
            0x00,
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            Instruction::i64Const.repr(),
            0x11,                             // ‭1236858285285558588‬   112A 340E ABF1 C93C‬
            0x2a,
            0x34,
            0x0e,
            0xab,
            0xf1,
            0xc9,
            0x3c,
            0x7f,                             // 9223372036854775807
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x32,                             // ‭3658975365245698789‬   ‭32C7 4AB5 6760 02E5‬
            0xc7,
            0x4a,
            0xb5,
            0x67,
            0x60,
            0x02,
            0xe5,
            0x0f,                             // ‭1111111123658796589‬   ‭F6B 75AE 17AA EE2D‬
            0x6b,
            0x75,
            0xae,
            0x17,
            0xaa,
            0xee,
            0x2d,
            Instruction::Max.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i64Const.repr(),
            0x7f,                             // 9223372036854775807
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_min_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x05,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x40,                             // 2.5
            0x20,
            0x00,
            0x00,
            0x41,                             // 25.5
            0xcc,
            0x00,
            0x00,
            0xc2,                             // -65.5
            0x83,
            0x00,
            0x00,
            0xc2,                             // -100.1
            0xc8,
            0x33,
            0x33,
            0x44,                             // 1000.1
            0x7a,
            0x06,
            0x66,
            Instruction::Min.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xc2,                             // -100.1
            0xc8,
            0x33,
            0x33,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_max_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x05,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x40,                             // 2.5
            0x20,
            0x00,
            0x00,
            0x41,                             // 25.5
            0xcc,
            0x00,
            0x00,
            0xc2,                             // -65.5
            0x83,
            0x00,
            0x00,
            0xc2,                             // -100.1
            0xc8,
            0x33,
            0x33,
            0x44,                             // 1000.1
            0x7a,
            0x06,
            0x66,
            Instruction::Max.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x44,                             // 1000.1
            0x7a,
            0x06,
            0x66,
            Instruction::Eq.repr(),          // Assert that operands are equal
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_eqz_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 1
            0x00,
            0x00,
            0x01,
            Instruction::If.repr(),
            0x00,
            Instruction::Eqz.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            Instruction::Eq.repr(),           // Assert 10 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 1
            0x00,
            0x00,
            0x01,
            Instruction::Eq.repr(),           // Assert 1 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_eqz_perform_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 0
            0x00,
            0x00,
            0x00,
            Instruction::If.repr(),
            0x00,
            Instruction::Eqz.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 0
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),           // Assert 0 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            Instruction::Eq.repr(),           // Assert 10 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_ne_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 3
            0x00,
            0x00,
            0x03,
            0x00,                             // 3
            0x00,
            0x00,
            0x03,
            Instruction::If.repr(),
            0x00,
            Instruction::Ne.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 9
            0x00,
            0x00,
            0x09,
            Instruction::Eq.repr(),           // Assert 9 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 9
            0x00,
            0x00,
            0x09,
            Instruction::Eq.repr(),           // Assert 9 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_ne_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 2
            0x00,
            0x00,
            0x02,
            0x00,                             // 3
            0x00,
            0x00,
            0x03,
            Instruction::If.repr(),
            0x00,
            Instruction::Ne.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            Instruction::Eq.repr(),           // Assert 5 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            Instruction::Eq.repr(),           // Assert 5 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_lt_signed_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            Instruction::If.repr(),
            0x00,
            Instruction::LtSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_lt_signed_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::LtSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -15
            0xff,
            0xff,
            0xf1,
            Instruction::Eq.repr(),           // Assert -15 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -15
            0xff,
            0xff,
            0xf1,
            Instruction::Eq.repr(),           // Assert -15 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_lt_unsigned_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            Instruction::If.repr(),
            0x00,
            Instruction::LtUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_lt_unsigned_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            Instruction::If.repr(),
            0x00,
            Instruction::LtUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 15
            0x00,
            0x00,
            0x0f,
            Instruction::Eq.repr(),           // Assert 15 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 15
            0x00,
            0x00,
            0x0f,
            Instruction::Eq.repr(),           // Assert 15 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_lt_unsigned_breaks_with_signed_operands() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::LtUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::UnsignedOperationSignedOperand));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_gt_signed_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::GtSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_gt_signed_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            Instruction::If.repr(),
            0x00,
            Instruction::GtSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -15
            0xff,
            0xff,
            0xf1,
            Instruction::Eq.repr(),           // Assert -15 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -15
            0xff,
            0xff,
            0xf1,
            Instruction::Eq.repr(),           // Assert -15 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_gt_unsigned_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            Instruction::If.repr(),
            0x00,
            Instruction::GtUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_gt_unsigned_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            Instruction::If.repr(),
            0x00,
            Instruction::GtUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 15
            0x00,
            0x00,
            0x0f,
            Instruction::Eq.repr(),           // Assert 15 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 15
            0x00,
            0x00,
            0x0f,
            Instruction::Eq.repr(),           // Assert 15 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_gt_unsigned_breaks_with_signed_operands() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::GtUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::UnsignedOperationSignedOperand));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_le_signed_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            Instruction::If.repr(),
            0x00,
            Instruction::LeSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -50
            0xff,
            0xff,
            0xce,
            Instruction::Eq.repr(),           // Assert -50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -50
            0xff,
            0xff,
            0xce,
            Instruction::Eq.repr(),           // Assert -50 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_le_signed_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::LeSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -20
            0xff,
            0xff,
            0xec,
            Instruction::Eq.repr(),           // Assert -20 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -20
            0xff,
            0xff,
            0xec,
            Instruction::Eq.repr(),           // Assert -20 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_le_unsigned_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            Instruction::If.repr(),
            0x00,
            Instruction::LeUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_le_unsigned_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            Instruction::If.repr(),
            0x00,
            Instruction::LeUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 20
            0x00,
            0x00,
            0x14,
            Instruction::Eq.repr(),           // Assert 20 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 20
            0x00,
            0x00,
            0x14,
            Instruction::Eq.repr(),           // Assert 20 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_le_unsigned_breaks_with_signed_operands() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            Instruction::If.repr(),
            0x00,
            Instruction::LeUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::UnsignedOperationSignedOperand));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_ge_signed_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::GeSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -50
            0xff,
            0xff,
            0xce,
            Instruction::Eq.repr(),           // Assert -50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -50
            0xff,
            0xff,
            0xce,
            Instruction::Eq.repr(),           // Assert -20 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_ge_signed_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::GeSigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -20
            0xff,
            0xff,
            0xec,
            Instruction::Eq.repr(),           // Assert -20 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0xff,                             // -20
            0xff,
            0xff,
            0xec,
            Instruction::Eq.repr(),           // Assert -20 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_ge_unsigned_performs_else_on_false() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            0x00,                             // 5
            0x00,
            0x00,
            0x05,
            Instruction::If.repr(),
            0x00,
            Instruction::GeUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 50 - fail test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 50
            0x00,
            0x00,
            0x32,
            Instruction::Eq.repr(),           // Assert 32 - pass test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_ge_unsigned_performs_if_on_true() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            0x00,                             // 10
            0x00,
            0x00,
            0x0a,
            Instruction::If.repr(),
            0x00,
            Instruction::GeUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 20
            0x00,
            0x00,
            0x14,
            Instruction::Eq.repr(),           // Assert 20 - pass test
            Instruction::End.repr(),
            Instruction::Else.repr(),
            0x00,
            Instruction::Mul.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::i32Const.repr(),
            0x00,                             // 20
            0x00,
            0x00,
            0x14,
            Instruction::Eq.repr(),           // Assert 20 - fail test
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn comparison_ge_unsigned_breaks_with_signed_operands() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::i32Const.repr(),
            Instruction::i32Const.repr(),
            0xff,                             // -5
            0xff,
            0xff,
            0xfb,
            0xff,                             // -10
            0xff,
            0xff,
            0xf6,
            Instruction::If.repr(),
            0x00,
            Instruction::GeUnsigned.repr(),
            Instruction::Add.repr(),
            Instruction::End.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::UnsignedOperationSignedOperand));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_abs_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xc1,                             // -10
            0x20,
            0x00,
            0x00,
            Instruction::Abs.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x41,                             // 10
            0x20,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_abs_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0xc0,                             // -10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Abs.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_neg_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x41,                             // 10.123
            0x21,
            0xf7,
            0xcf,
            Instruction::Neg.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xc1,                             // -10.123
            0x21,
            0xf7,
            0xcf,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_neg_f32_2() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xc1,                             // -10.123
            0x21,
            0xf7,
            0xcf,
            Instruction::Neg.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x41,                             // 10.123
            0x21,
            0xf7,
            0xcf,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_neg_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Neg.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0xc0,                             // -10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_neg_f64_2() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0xc0,                             // -10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Neg.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_div_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x41,                             // 10
            0x20,
            0x00,
            0x00,
            0xc0,                             // -2.5
            0x20,
            0x00,
            0x00,
            Instruction::Div.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xc0,                             // -4
            0x80,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_div_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f64Const.repr(),
            Instruction::f64Const.repr(),
            0xc0,                             // -10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            0xc0,                             // -2
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Div.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 5.0615
            0x14,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_ceil_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2.3
            0x13,
            0x33,
            0x33,
            Instruction::Ceil.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 3
            0x40,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_ceil_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 3.9
            0x0f,
            0x33,
            0x33,
            0x33,
            0x33,
            0x33,
            0x33,
            Instruction::Ceil.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 4
            0x10,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_floor_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2.3
            0x13,
            0x33,
            0x33,
            Instruction::Floor.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_floor_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 3.9
            0x0f,
            0x33,
            0x33,
            0x33,
            0x33,
            0x33,
            0x33,
            Instruction::Floor.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 3
            0x08,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_trunc_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2.3
            0x13,
            0x33,
            0x33,
            Instruction::Trunc.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_trunc_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 3.9
            0x0f,
            0x33,
            0x33,
            0x33,
            0x33,
            0x33,
            0x33,
            Instruction::Trunc.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 3
            0x08,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_nearest_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 3.499
            0x5f,
            0xef,
            0x9e,
            Instruction::Nearest.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 3
            0x40,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_nearest_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 3.50000000000001
            0x0c,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x17,
            Instruction::Nearest.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 4
            0x10,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_copysign_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f32Const.repr(),
            Instruction::f32Const.repr(),
            0x41,                             // 10.123
            0x21,
            0xf7,
            0xcf,
            0xc0,                             // -2.5
            0x20,
            0x00,
            0x00,
            Instruction::CopySign.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xc1,                             // -10.123
            0x21,
            0xf7,
            0xcf,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_copysign_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x02,
            0x00,
            Instruction::f64Const.repr(),
            Instruction::f64Const.repr(),
            0xc0,                             // -10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            0x40,                             // 4
            0x10,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::CopySign.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_sqrt_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 5.29
            0xa9,
            0x47,
            0xae,
            Instruction::Sqrt.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0x40,                             // 2.3
            0x13,
            0x33,
            0x33,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_performs_sqrt_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 6.25
            0x19,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Sqrt.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0x40,                             // 2.5
            0x04,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            Instruction::Eq.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_ne!(execute_vm_code_common(block), Err(VmError::AssertionFailed));
    }

    #[test]
    #[rustfmt::skip]
    fn it_fails_with_negative_sqrt_f32() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f32Const.repr(),
            0xc0,                             // -2.5
            0x20,
            0x00,
            0x00,
            Instruction::Sqrt.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::DivideByZero));
    }

    #[test]
    #[rustfmt::skip]
    fn it_fails_with_negative_sqrt_f64() {
        let block: Vec<u8> = vec![
            Instruction::Begin.repr(),
            0x00,                             // 0 Arity
            Instruction::Nop.repr(),
            Instruction::PushOperand.repr(),
            0x01,
            0x00,
            Instruction::f64Const.repr(),
            0xc0,                             // -10.123
            0x24,
            0x3e,
            0xf9,
            0xdb,
            0x22,
            0xd0,
            0xe5,
            Instruction::Sqrt.repr(),
            Instruction::Nop.repr(),
            Instruction::End.repr()
        ];

        assert_eq!(execute_vm_code_common(block), Err(VmError::DivideByZero));
    }
}
