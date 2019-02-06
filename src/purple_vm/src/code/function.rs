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

use primitives::r#type::VmType;
use instruction_set::Instruction;

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
    pub return_type: VmType
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
            Some(Instruction::Loop)  => self.find_block_len(idx),
            Some(Instruction::If)    => self.find_block_len(idx),
            Some(Instruction::Else)  => self.find_block_len(idx),
            _                  => panic!("The length of a block can only be queried for a control flow instruction!")
        }
    }

    fn find_block_len(&self, idx: usize) -> usize {
        let mut result_len: usize = 0;
        let len = self.block.len();
        
        for i in idx..len {
            result_len += 1;

            let op = Instruction::from_repr(self.block[i]).unwrap();

            if let Instruction::End = op {
                break;
            }
        }

        result_len
    }
}