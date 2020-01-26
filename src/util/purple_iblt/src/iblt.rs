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

  Rust implementation of IBLT data-structure based on the following implementation
  by Gavin Andresen: https://github.com/gavinandresen/IBLT_Cplusplus
*/

#![allow(unused, clippy::needless_range_loop)]

use crate::error::IBLTError;
use crc32fast::Hasher;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian, LittleEndian};

const HASH_CHECK: u8 = 11;

#[derive(Clone)]
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
        if hash_functions == 0 {
            return Err(IBLTError::BadParameter);
        }

        if table_size % hash_functions as usize != 0 {
            return Err(IBLTError::BadParameter);
        }
        
        Ok(PurpleIBLT {
            table: vec![TableEntry::new(value_size as usize); table_size],
            value_size,
            hash_functions,
        })
    } 

    pub fn insert(&mut self, k: u64, val: &[u8]) -> Result<(), IBLTError> {
        self.insert_or_delete(k, val, 1)
    }

    pub fn remove(&mut self, k: u64, val: &[u8]) -> Result<(), IBLTError> {
        self.insert_or_delete(k, val, -1)
    }

    pub fn get(&self, k: u64) -> Option<Vec<u8>> {
        let mut result = Vec::new();
        let buckets = self.table.len() / self.hash_functions as usize;

        for i in 0..self.hash_functions {
            let start_idx = (i as usize) * buckets;

            // Hash key
            let hash = hash_value(i, &encode_le_u64!(k));

            let entry = &self.table[start_idx + ((hash as usize) % buckets)];

            if entry.is_empty() {
                return None;
            } else if entry.is_pure() {
                if entry.key_sum == k {
                    result = entry.value_sum.clone();
                    return Some(result);
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }

        None
    }

    pub fn subtract(&mut self, other: &PurpleIBLT) -> Result<(), IBLTError> {
        unimplemented!();
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PurpleIBLT, IBLTError> {
        unimplemented!();
    }

    fn insert_or_delete(&mut self, k: u64, val: &[u8], insert_or_delete: i32) -> Result<(), IBLTError> {
        if val.len() != self.value_size as usize {
            return Err(IBLTError::BadParameter);
        }

        let buckets = self.table.len() / self.hash_functions as usize;
        
        for i in 0..self.hash_functions {
            let start_idx = (i as usize) * buckets;
            
            // Hash key
            let hash = hash_value(i, &encode_le_u64!(k));

            // Update entry
            let mut entry = &mut self.table[start_idx + ((hash as usize) % buckets)];
            entry.count += insert_or_delete;
            entry.key_sum ^= k;
            entry.key_check ^= hash_value(HASH_CHECK, &encode_le_u64!(k));
        
            if entry.is_empty() {
                entry.value_sum = vec![0; self.value_size as usize];
            } else {
                for i in 0..self.value_size as usize {
                    entry.value_sum[i] ^= val[i];
                }
            }
        }

        Ok(())
    } 
}

fn hash_value(i: u8, val: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(&[i]);
    hasher.update(val);
    hasher.finalize()
}

#[derive(Clone)]
struct TableEntry {
    count: i32,
    key_check: u32,
    key_sum: u64,
    value_sum: Vec<u8>,
}

impl TableEntry {
    pub fn new(value_size: usize) -> TableEntry {
        TableEntry {
            count: 0,
            key_check: 0,
            key_sum: 0,
            value_sum: vec![0; value_size]
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0 && self.key_sum == 0 && self.key_check == 0
    }

    pub fn is_pure(&self) -> bool {
        if self.count == 1 || self.count == -1 {
            let check = hash_value(HASH_CHECK, &encode_le_u64!(self.key_sum));
            return self.key_check == check;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get() {
        let mut iblt = PurpleIBLT::new(20, 8, 4).unwrap();
        let k = 34;
        let v = 3243;
        let v_le = encode_le_u64!(v);

        assert!(iblt.insert(k, &v_le).is_ok());
        assert_eq!(iblt.get(k), Some(v_le.clone()));
    }

    #[test]
    fn insert_remove_get() {
        let mut iblt = PurpleIBLT::new(20, 8, 4).unwrap();
        let k = 34;
        let v = 3243;
        let v_le = encode_le_u64!(v);

        assert!(iblt.insert(k, &v_le).is_ok());
        assert!(iblt.remove(k, &v_le).is_ok());
        assert!(iblt.get(k).is_none());
    }
}