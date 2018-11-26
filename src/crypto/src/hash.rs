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

use rand::Rng;
use quickcheck::Arbitrary;
use blake2::VarBlake2b;
use blake2::digest::{Input, VariableOutput};
use std::convert::{AsMut, AsRef};
use std::default::Default;
use hashdb::Hasher;
use blake_hasher::BlakeHasher;

pub const HASH_BYTES: usize = 32;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

impl Default for Hash {
    fn default() -> Self {
        let mut buf = Vec::with_capacity(HASH_BYTES);
        let mut result = [0; HASH_BYTES];

        for _ in 0..HASH_BYTES {
            buf.push(0);
        }

        result.copy_from_slice(&buf);

        Hash(result)
    }
}

impl Hasher for Hash {
    type Out = Hash;
    type StdHasher = BlakeHasher;
    const LENGTH: usize = HASH_BYTES;

    fn hash(bin: &[u8]) -> Self::Out {
        hash_slice(bin)
    }
}

impl AsMut<[u8]> for Hash {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub fn hash_slice(val: &[u8]) -> Hash {
    let mut hasher = VarBlake2b::new(HASH_BYTES).unwrap();
    let mut result: [u8; HASH_BYTES] = [0; HASH_BYTES];

    hasher.input(&val);
    hasher.variable_result(|r| {
        result.copy_from_slice(r);
    });

    Hash(result)
}

impl Arbitrary for Hash {
    fn arbitrary<G : quickcheck::Gen>(_g: &mut G) -> Hash {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| {
            rng.gen_range(1, 255)
        }).collect();

        let mut result = [0; 32];
        result.copy_from_slice(&bytes);

        Hash(result)
    }
}

// #[test]
// fn hash() {
//     let hash1 = hash_slice(b"");
//     let hash2 = hash_slice(b"The quick brown fox jumps over the lazy dog");
//     let result1 = hex::encode(hash1.to_vec().as_slice());
//     let result2 = hex::encode(hash2.to_vec().as_slice());

//     assert_eq!(
//         result1,
//         "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
//     );
//     assert_eq!(
//         result2,
//         "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812"
//     );
// }
