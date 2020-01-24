/*
  Copyright (C) 2018-2020 The Purple Core Developers.
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

use crate::error::IBLTError;

pub struct PurpleIBLT {
    /// IBLT table
    table: Vec<TableEntry>,

    /// The size of a value in the table 
    value_size: u16,

    /// The number of hash functions performed on values i.e. the k parameter
    hash_functions: u8,
}

impl PurpleIBLT {
    pub fn new(table_size: usize, value_size: u16, hash_functions: u8) -> Result<PurpleIBLT, IBLTError> {
        Ok(PurpleIBLT {
            table: Vec::with_capacity(table_size),
            value_size,
            hash_functions,
        })
    } 
}

struct TableEntry {
    count: u32,
    key_check: u32,
    key_sum: u64,
    value_sum: Vec<u8>,
}