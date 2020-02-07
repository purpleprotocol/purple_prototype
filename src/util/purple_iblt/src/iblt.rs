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

#![allow(unused, clippy::never_loop, clippy::needless_range_loop)]

use crate::error::IBLTError;
use crc32fast::Hasher;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian, LittleEndian};
use hashbrown::HashMap;
use std::io::Cursor;

const HASH_CHECK: u8 = 11;

#[derive(Debug, Clone, PartialEq)]
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
                    return Some(entry.value_sum.clone());
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }

        None
    }

    /// Returns a new IBLT with the symmetric difference of `self` and `other`.
    pub fn symmetric_diff(&self, other: &PurpleIBLT) -> Result<PurpleIBLT, IBLTError> {
        if self.hash_functions != other.hash_functions {
            return Err(IBLTError::BadParameter);
        }

        if self.value_size != other.value_size {
            return Err(IBLTError::BadParameter);
        }

        if self.table.len() != other.table.len() {
            return Err(IBLTError::BadParameter);
        }

        let mut result = self.clone();

        for i in 0..self.table.len() {
            let mut e1 = &mut result.table[i];
            let e2 = &other.table[i];

            e1.count -= e2.count;
            e1.key_sum ^= e2.key_sum;
            e1.key_check ^= e2.key_check;

            if e1.is_empty() {
                e1.value_sum = vec![0; self.value_size as usize];
            } else {
                for i in 0..self.value_size as usize {
                    e1.value_sum[i] ^= e2.value_sum[i];
                }
            }
        }

        Ok(result)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.write_u8(self.hash_functions);
        buf.write_u16::<BigEndian>(self.value_size);
        buf.write_u32::<BigEndian>(self.table.len() as u32);

        // Write entries
        for entry in self.table.iter() {
            buf.write_i32::<BigEndian>(entry.count);
            buf.write_u32::<BigEndian>(entry.key_check);
            buf.write_u64::<BigEndian>(entry.key_sum);
            buf.extend_from_slice(&entry.value_sum);
        }

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PurpleIBLT, IBLTError> {
        let mut rdr = Cursor::new(bytes.to_vec());

        let hash_functions = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(IBLTError::ParseError);
        };

        rdr.set_position(1);

        let value_size = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err(IBLTError::ParseError);
        };

        rdr.set_position(3);

        let table_size = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(IBLTError::ParseError);
        };

        let mut iblt = PurpleIBLT::new(table_size as usize, value_size, hash_functions)?;

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..7).collect();
        let mut idx = 0;
        
        // Decode entries
        while buf.len() != 0 {
            if buf.len() >= (4 + 4 + 8 + value_size as usize) {
                let mut rdr = Cursor::new(buf);
                
                let count = if let Ok(result) = rdr.read_i32::<BigEndian>() {
                    result
                } else {
                    return Err(IBLTError::ParseError);
                };

                rdr.set_position(4);

                let key_check = if let Ok(result) = rdr.read_u32::<BigEndian>() {
                    result
                } else {
                    return Err(IBLTError::ParseError);
                };

                rdr.set_position(8);

                let key_sum = if let Ok(result) = rdr.read_u64::<BigEndian>() {
                    result
                } else {
                    return Err(IBLTError::ParseError);
                };

                // Consume cursor
                let mut buffer: Vec<u8> = rdr.into_inner();
                let _: Vec<u8> = buffer.drain(..16).collect();
                let value_sum = buffer.drain(..(value_size as usize)).collect();

                let entry = TableEntry {
                    count,
                    key_check,
                    key_sum,
                    value_sum,
                };

                iblt.table[idx] = entry;
                idx += 1;
                buf = buffer;
            } else {
                return Err(IBLTError::ParseError);
            };
        }

        Ok(iblt)
    }

    pub fn list_entries_non_destructive(&self, positive: &mut HashMap<u64, Vec<u8>>, negative: &mut HashMap<u64, Vec<u8>>) -> bool {
        self.clone().list_entries_destructive(positive, negative)
    }

    pub fn list_entries_destructive(&mut self, positive: &mut HashMap<u64, Vec<u8>>, negative: &mut HashMap<u64, Vec<u8>>) -> bool {        
        let mut erased = 1;

        while erased > 0 {
            let mut to_delete: Vec<(u64, Vec<u8>, i32)> = Vec::new();
            erased = 0;

            for entry in self.table.iter() {
                if entry.is_pure() {
                    if entry.count == 1 {
                        positive.insert(entry.key_sum, entry.value_sum.clone());
                    } else {
                        negative.insert(entry.key_sum, entry.value_sum.clone());
                    }

                    to_delete.push((entry.key_sum, entry.value_sum.clone(), entry.count));
                }
            }

            for (key_sum, value_sum, count) in to_delete {
                self.insert_or_delete(key_sum, &value_sum, -count);
                erased += 1;
            }
        }

        let r = self.table.len() / (self.hash_functions as usize);

        for i in 0..r {
            if !self.table[i].is_empty() {
                return false;
            }
        }

        true
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

#[derive(Debug, Clone, PartialEq)]
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

use quickcheck::Arbitrary;

impl Arbitrary for PurpleIBLT {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> PurpleIBLT {
        let mut iblt = PurpleIBLT::new(20, 8, 4).unwrap();

        // Insert 100 random `(k, v)` pairs
        for _ in 0..100 {
            let k: u64 = Arbitrary::arbitrary(g);
            let v: u64 = Arbitrary::arbitrary(g);
            let v_le = encode_le_u64!(v);
            
            iblt.insert(k, &v_le).unwrap();
        }

        iblt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

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

    #[test]
    fn symmetric_diff() {
        let mut iblt1 = PurpleIBLT::new(20, 8, 4).unwrap();
        let mut iblt2 = PurpleIBLT::new(20, 8, 4).unwrap();
        let k_1 = 342;
        let v_1 = 3244323;
        let v_1_le = encode_le_u64!(v_1);
        let k_2 = 34;
        let v_2 = 3243;
        let v_2_le = encode_le_u64!(v_2);
        let k_3 = 37;
        let v_3 = 32463;
        let v_3_le = encode_le_u64!(v_3);

        assert!(iblt1.insert(k_1, &v_1_le).is_ok());
        assert!(iblt2.insert(k_1, &v_1_le).is_ok());
        assert!(iblt1.insert(k_2, &v_2_le).is_ok());
        assert!(iblt2.insert(k_3, &v_3_le).is_ok());
        assert!(iblt1.get(k_1).is_some());
        assert!(iblt1.get(k_2).is_some());
        assert!(iblt1.get(k_3).is_none());
        assert!(iblt2.get(k_1).is_some());
        assert!(iblt2.get(k_2).is_none());
        assert!(iblt2.get(k_3).is_some());

        let result = iblt1.symmetric_diff(&iblt2).unwrap();
        assert!(result.get(k_1).is_none());
        assert!(result.get(k_2).is_some());
        assert!(result.get(k_3).is_some());
    }

    #[test]
    fn list_entries() {
        let mut iblt1 = PurpleIBLT::new(20, 8, 4).unwrap();
        let mut iblt2 = PurpleIBLT::new(20, 8, 4).unwrap();
        let k_1 = 342;
        let v_1 = 3244323;
        let v_1_le = encode_le_u64!(v_1);
        let k_2 = 34;
        let v_2 = 3243;
        let v_2_le = encode_le_u64!(v_2);
        let k_3 = 37;
        let v_3 = 32463;
        let v_3_le = encode_le_u64!(v_3);

        assert!(iblt1.insert(k_1, &v_1_le).is_ok());
        assert!(iblt2.insert(k_1, &v_1_le).is_ok());
        assert!(iblt1.insert(k_2, &v_2_le).is_ok());
        assert!(iblt2.insert(k_3, &v_3_le).is_ok());
        assert!(iblt1.get(k_1).is_some());
        assert!(iblt1.get(k_2).is_some());
        assert!(iblt1.get(k_3).is_none());
        assert!(iblt2.get(k_1).is_some());
        assert!(iblt2.get(k_2).is_none());
        assert!(iblt2.get(k_3).is_some());

        let mut result = iblt1.symmetric_diff(&iblt2).unwrap();
        assert!(result.get(k_1).is_none());
        assert!(result.get(k_2).is_some());
        assert!(result.get(k_3).is_some());

        let mut positive = HashMap::new();
        let mut negative = HashMap::new();
        result.list_entries_destructive(&mut positive, &mut negative);

        assert!(positive.get(&k_1).is_none());
        assert!(positive.get(&k_2).is_some());
        assert!(positive.get(&k_3).is_none());
        assert!(negative.get(&k_1).is_none());
        assert!(negative.get(&k_2).is_none());
        assert!(negative.get(&k_3).is_some());
    }

    quickcheck! {
        fn serialize_deserialize(iblt: PurpleIBLT) -> bool {
            iblt == PurpleIBLT::from_bytes(&PurpleIBLT::to_bytes(&iblt)).unwrap()
        }
    }
}