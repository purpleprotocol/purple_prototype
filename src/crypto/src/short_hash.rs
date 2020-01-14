/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

use crate::hash::Hash;
use crc32fast::Hasher as CrcHasher;
use quickcheck::Arbitrary;
use rand::Rng;
use std::default::Default;

pub const SHORT_HASH_BYTES: usize = 8;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
/// A short (8bytes) representation of a `Hash` which has 32 bytes.
pub struct ShortHash(pub [u8; SHORT_HASH_BYTES]);

impl ShortHash {
    pub fn from_hash(hash: &Hash) -> ShortHash {
        let mut short_hash = [0; SHORT_HASH_BYTES];
        let short_bytes = &hash.0[..SHORT_HASH_BYTES];

        short_hash.copy_from_slice(short_bytes);
        ShortHash(short_hash)
    }

    /// Converts the `ShortHash` to an unique integer representation.
    pub fn to_u64(&self) -> u64 {
        let mut hasher = CrcHasher::new();
        hasher.update(&self.0);
        hasher.finalize() as u64
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(SHORT_HASH_BYTES);

        for byte in &self.0 {
            result.push(*byte);
        }

        result
    }

    pub fn random() -> ShortHash {
        let random_bytes = rand::thread_rng().gen::<[u8; SHORT_HASH_BYTES]>();
        ShortHash(random_bytes)
    }
}

impl Default for ShortHash {
    fn default() -> Self {
        let mut buf = Vec::with_capacity(SHORT_HASH_BYTES);
        let mut result = [0; SHORT_HASH_BYTES];

        for _ in 0..SHORT_HASH_BYTES {
            buf.push(0);
        }

        result.copy_from_slice(&buf);

        ShortHash(result)
    }
}

impl std::fmt::Debug for ShortHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ShortHash({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for ShortHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
