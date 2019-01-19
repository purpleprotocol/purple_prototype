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
    /// A contract is composed of 2 sections:
    /// 1) The imports section 
    /// 2) The functions section
    ///
    /// Everything is encoded using Big Endian
    ///
    /// The binary structure of a contract is the following:
    /// 1) Version               - 8bits                - The version of the instruction set.
    /// 2) Imports length        - 16bits               - The length of the imports section.
    /// 3) Functions length      - 16bits               - The length of the functions section.
    /// 4) Imports payload       - Variable length      - The imports section data.
    /// 5) Functions payload     - Variable length      - The functions section data.
    ///
    /// The imports section describes function imports from
    /// other contracts. It has the following format: 
    /// 1) Addresses length      - 16bits               - The length of the addresses field.
    /// 2) Data length           - 16bits               - The length of the data field. 
    /// 3) Addresses payload     - Variable length      - The addresses field. Contains all contract addresses that can be called.
    /// 4) Data payload          - Variable length      - The imports section entries.
    ///
    /// An entry in the imports section has 
    /// the following format:
    /// 1) Functon name length   - 8bits                - The length of the function name field. 
    /// 2) Address index         - 16bits               - The index of the address from the address index space.
    /// 3) Functon name          - Variable length      - The name of the function.
    ///
    /// 
    /// The functions section describes the functions that
    /// are defined in the contract.
    ///
    /// An entry in the functions section has the following format:
    /// 1) Function name length  - 8bits                - The length of the function name field.
    /// 2) Arity                 - 8bits                - The arity of the function.
    /// 3) Return type           - 8bits                - The return type of the function.
    /// 4) Block length          - 16bits               - The length of the block field.
    /// 5) Function name         - Variable length      - The name of the function. Must be valid utf8.
    /// 6) Argument types        - Variable length      - The types of the arguments.
    /// 7) Block                 - Variable length      - The function's block of code.
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

