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

const VM_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct Code(Vec<u8>);

impl Code {
    pub fn new(code: &[u8]) -> Code {
        Code(code.to_vec())
    }

    /// Performs validations on the provided code.
    ///
    /// The source code is a set of function signatures, each 
    /// of which has a representing block of instructions.
    ///   
    ///
    /// The structure of a contract is the following:
    /// 1) Version       - 8bits              - The version of the instruction set
    /// 2) Data          - Arbitrary length   - The data field. This field contains all of the contract sections.
    ///
    /// The data field is composed of 3 sections:
    /// 1) The imports section 
    /// 2) The exports section
    /// 3) The functions section
    ///
    /// The imports section describes function imports from
    /// other contracts. It has the following format: 
    /// 1) Addresses length   - 16bits 
    /// 2) Data length        - 16bits
    /// 3) Addresses payload  - Binary of addresses length
    /// 4) Data payload       - Binary of data length
    ///
    /// An entry in the imports section has 
    /// the following format:
    /// 1) Functon name length   - 8bits
    /// 2) Address index         - 16bits  
    /// 3) Functon name          - Binary of function name length
    ///
    /// The exports section describes the functions exported
    /// from the contract. It has the following format:
    /// TODO: Add exports section definitions
    /// TODO: Add functions section definitions
    pub fn validate(&self) -> bool {
        unimplemented!(); 
    }
        
}

fn validate_block(block: &[u8]) -> bool {
    // A block cannot be empty
    if block.len() <= 2 {
        return false;
    }

    let first = block[0];
    let last = block[block.len()-1];

    // The first instruction must always 
    // be a `Block` instruction.
    let _: Result<(), ()> = match Instruction::from_repr(first) {
        Some(Instruction::Block) => Ok(()),
        _                        => return false
    };

    // The last instruction must always
    // be an `End` instruction. 
    let _: Result<(), ()> = match Instruction::from_repr(last) {
        Some(Instruction::End) => Ok(()),
        _                      => return false
    };

    true
}

#[cfg(test)]
#[test]
fn validate_block_it_fails_on_invalid_first_instruction() {
    let block = vec![Instruction::Nop.repr(), Instruction::Nop.repr(), Instruction::End.repr()];
    assert!(!validate_block(&block));
}

#[cfg(test)]
#[test]
fn validate_block_it_fails_on_invalid_last_instruction() {
    let block = vec![Instruction::Block.repr(), Instruction::Nop.repr(), Instruction::Nop.repr()];
    assert!(!validate_block(&block));
}

#[cfg(test)]
#[test]
fn validate_block_it_fails_on_empty_block() {
    let block = vec![Instruction::Block.repr(), Instruction::End.repr()];
    assert!(!validate_block(&block));
}

