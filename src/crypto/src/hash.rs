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

extern crate hex;

use blake2::{Blake2s, Digest};
const HASH_BYTES: usize = 32;

#[derive(Serialize, Deserialize, Debug)]
pub struct Hash(pub [u8; HASH_BYTES]);

impl Hash {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(HASH_BYTES);

        for byte in &self.0 {
            result.push(*byte);
        }

        result
    }
}

pub fn hash_slice(val: &[u8]) -> Hash {
    let mut hasher = Blake2s::new();
    let mut result: [u8; HASH_BYTES] = [0; HASH_BYTES];

    hasher.input(&val);
    result.copy_from_slice(hasher.result().as_slice());
    
    Hash(result)  
}

#[test]
fn hash() {
    let hash1   = hash_slice(b"");
    let hash2   = hash_slice(b"The quick brown fox jumps over the lazy dog");
    let result1 = hex::encode(hash1.to_vec().as_slice());
    let result2 = hex::encode(hash2.to_vec().as_slice());
    
    assert_eq!(result1, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    assert_eq!(result2, "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812");
}