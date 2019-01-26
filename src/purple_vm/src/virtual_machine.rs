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
use module::Module;
use patricia_trie::{TrieMut, TrieDBMut};
use persistence::{BlakeDbHasher, Codec};

#[derive(Debug)]
pub struct Vm {
    modules: Vec<Module>,
    frame_stack: Stack<Frame<VmValue>>,
    operand_stack: Stack<VmValue>
}

#[derive(Clone, Debug)]
pub enum VmError {
    /// The module is not loaded.
    NoModule,

    /// The function with the given index is not defined.
    NoFun,

    /// The module containing the function imported at 
    /// (module idx, import idx) is not loaded. 
    NotLoaded(usize, usize),

    /// The module is already loaded.
    AlreadyLoaded,

    /// I32 Overflow
    I32Overflow,

    /// I64 Overflow
    I64Overflow,

    /// F32 Overflow
    F32Overflow,

    /// F64 Overflow
    F64Overflow,

}

impl Vm {
    pub fn new() -> Vm {
        Vm {
            modules: Vec::new(),
            frame_stack: Stack::<Frame<VmValue>>::new(),
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
    pub fn execute(&mut self, trie: &mut TrieDBMut<BlakeDbHasher, Codec>, module_idx: usize, fun_idx: usize, gas: u64) -> Result<u64, VmError> {
        unimplemented!();
    }
}