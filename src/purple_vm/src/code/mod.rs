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

pub mod function;
pub mod import;
pub mod transition;
mod validator;

use self::validator::Validator;
use byteorder::{BigEndian, ReadBytesExt};
use function::Function;
use hashbrown::HashSet;
use import::Import;
use instruction_set::Instruction;
use module::Module;
use primitives::r#type::VmType;
use std::hash::Hash;
use std::io::Cursor;
use std::str;

const VM_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct Code(Vec<u8>);

impl Code {
    pub fn new(code: &[u8]) -> Code {
        Code(code.to_vec())
    }

    /// Converts the binary code to it's internal vm representation.
    pub fn to_mod(&self) -> Module {
        unimplemented!();
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
    /// Everything is encoded in Big Endian.
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
    /// 3) Function name          - Variable length      - The name of the function.
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
    pub fn validate(&mut self) -> bool {
        // The code cannot be empty.
        if self.0.len() == 0 {
            return false;
        }

        let mut cursor = Cursor::new(&mut self.0);

        // Check version byte
        match cursor.read_u8() {
            Ok(byte) => {
                if byte != VM_VERSION {
                    return false;
                }
            }
            _ => return false,
        };

        cursor.set_position(1);

        let imports_len = match cursor.read_u16::<BigEndian>() {
            Ok(result) => result,
            _ => return false,
        };

        cursor.set_position(3);

        let functions_len = match cursor.read_u16::<BigEndian>() {
            Ok(result) => result,
            _ => return false,
        };

        // A contract cannot contain empty sections
        if imports_len == 0 || functions_len == 0 {
            return false;
        }

        // Consume cursor
        let buf = cursor.into_inner();
        let _: Vec<u8> = buf.drain(..5).collect();

        let imports_section = if buf.len() > imports_len as usize {
            let result: Vec<u8> = buf.drain(..imports_len as usize).collect();
            result
        } else {
            return false;
        };

        let mut functions_section = if buf.len() == functions_len as usize {
            let result: Vec<u8> = buf.drain(..functions_len as usize).collect();
            result
        } else {
            return false;
        };

        // Decode imports section
        let mut cursor = Cursor::new(imports_section);

        let addresses_len = match cursor.read_u16::<BigEndian>() {
            Ok(result) => result,
            _ => return false,
        };

        if addresses_len % 33 != 0 {
            return false;
        }

        cursor.set_position(2);

        let imports_len = match cursor.read_u16::<BigEndian>() {
            Ok(result) => result,
            _ => return false,
        };

        // Consume cursor
        let mut buf = cursor.into_inner();
        let _: Vec<u8> = buf.drain(..4).collect();

        let mut encoded_addresses = if buf.len() > addresses_len as usize {
            let result: Vec<u8> = buf.drain(..imports_len as usize).collect();
            result
        } else {
            return false;
        };

        let mut encoded_imports = if buf.len() == imports_len as usize {
            let result: Vec<u8> = buf.drain(..imports_len as usize).collect();
            result
        } else {
            return false;
        };

        let mut addresses: Vec<[u8; 33]> = Vec::with_capacity((addresses_len / 33) as usize);
        let mut imports: Vec<Import> = Vec::new();

        // Decode addresses
        loop {
            if encoded_addresses.len() == 0 {
                break;
            }

            let mut buf = [0; 33];
            let result: Vec<u8> = encoded_addresses.drain(..33).collect();

            // Only contract addresses are allowed
            if result[0] != 0x04 {
                return false;
            }

            buf.copy_from_slice(&result);
            addresses.push(buf);
        }

        // Decode imports
        loop {
            if encoded_imports.len() == 0 {
                break;
            }

            let mut cursor = Cursor::new(&mut encoded_imports);

            let function_name_len = match cursor.read_u8() {
                Ok(result) => result,
                _ => return false,
            };

            cursor.set_position(1);

            let address_idx = match cursor.read_u16::<BigEndian>() {
                Ok(result) => result,
                _ => return false,
            };

            // Invalid in case of out of bounds index
            if address_idx as usize > addresses.len() - 1 {
                return false;
            }

            let buf = cursor.into_inner();
            let _: Vec<u8> = buf.drain(..3).collect();

            let function_name = if buf.len() >= function_name_len as usize {
                let result: Vec<u8> = buf.drain(..function_name_len as usize).collect();

                match str::from_utf8(&result) {
                    Ok(result) => result.to_owned(),
                    _ => return false,
                }
            } else {
                return false;
            };

            let import = Import {
                addr_idx: address_idx,
                function_name: function_name,
            };

            imports.push(import);
        }

        // Decode functions section
        let mut functions: Vec<Function> = Vec::new();

        loop {
            if functions_section.len() == 0 {
                break;
            }

            let mut cursor = Cursor::new(&mut functions_section);

            let function_name_len = match cursor.read_u8() {
                Ok(result) => result,
                _ => return false,
            };

            cursor.set_position(1);

            let arity = match cursor.read_u8() {
                Ok(result) => result,
                _ => return false,
            };

            cursor.set_position(2);

            let return_type = match cursor.read_u8() {
                Ok(result) => VmType::from_op(result),
                _ => return false,
            };

            let return_type = match return_type {
                Some(result) => result,
                None => return false,
            };

            cursor.set_position(3);

            let block_len = match cursor.read_u16::<BigEndian>() {
                Ok(result) => result,
                _ => return false,
            };

            let buf = cursor.into_inner();
            let _: Vec<u8> = buf.drain(..5).collect();

            let function_name = if buf.len() > function_name_len as usize {
                let result: Vec<u8> = buf.drain(..function_name_len as usize).collect();

                match str::from_utf8(&result) {
                    Ok(result) => result.to_owned(),
                    _ => return false,
                }
            } else {
                return false;
            };

            let arguments = if buf.len() > arity as usize {
                let result: Option<Vec<VmType>> = buf
                    .drain(..function_name_len as usize)
                    .map(|v| VmType::from_op(v))
                    .collect();

                match result {
                    Some(result) => result,
                    None => return false,
                }
            } else {
                return false;
            };

            let block = if buf.len() >= block_len as usize {
                let result: Vec<u8> = buf.drain(..block_len as usize).collect();
                result
            } else {
                return false;
            };

            if !validate_block(&block, return_type, &arguments) {
                return false;
            }

            let function = Function {
                arity: arity,
                name: function_name,
                arguments: arguments,
                block: block,
                return_type: Some(return_type),
            };

            functions.push(function);
        }

        // Check for unique function names
        let imports_names: Vec<&str> = imports.iter().map(|i| i.function_name.as_str()).collect();

        let functions_names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();

        if !has_unique_elements(imports_names) || !has_unique_elements(functions_names) {
            return false;
        }

        true
    }
}

fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

fn validate_block(block: &[u8], return_type: VmType, argv: &[VmType]) -> bool {
    let mut validator = Validator::new();

    for byte in block {
        validator.push_op(*byte);

        // The validator cannot continue i.e. the input is invalid
        if validator.done() {
            return false;
        }
    }

    validator.valid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_it_fails_on_empty_code() {
        let mut code = Code::new(&[]);
        assert!(!code.validate());
    }

    #[test]
    fn validate_fails_on_bad_vm_version() {
        let mut code = Code::new(&[0x03, 0x00, 0x01, 0x00, 0x01]);
        assert!(!code.validate());
    }

    #[test]
    fn validate_fails_on_empty_sections() {
        let mut code1 = Code::new(&[0x01, 0x00, 0x00, 0x00, 0x01]);
        let mut code2 = Code::new(&[0x01, 0x00, 0x01, 0x00, 0x00]);
        let mut code3 = Code::new(&[0x01, 0x00, 0x00, 0x00, 0x00]);

        assert!(!code1.validate());
        assert!(!code2.validate());
        assert!(!code3.validate());
    }
}

#[cfg(test)]
#[test]
fn validate_block_it_fails_on_invalid_first_instruction() {
    let block = vec![
        Instruction::Nop.repr(),
        Instruction::Nop.repr(),
        Instruction::End.repr(),
    ];
    assert!(!validate_block(&block, VmType::I32, &[]));
}

#[cfg(test)]
#[test]
fn validate_block_it_fails_on_invalid_last_instruction() {
    let block = vec![
        Instruction::Begin.repr(),
        Instruction::Nop.repr(),
        Instruction::Nop.repr(),
    ];
    assert!(!validate_block(&block, VmType::I32, &[]));
}

#[cfg(test)]
#[test]
fn validate_block_it_fails_on_empty_block() {
    let block = vec![Instruction::Begin.repr(), Instruction::End.repr()];
    assert!(!validate_block(&block, VmType::I32, &[]));
}
