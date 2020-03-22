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

use crate::hash::*;
use merkle_light::hash::Algorithm;
use std::default::Default;
use std::hash::Hasher;
use std::io::Write;
use std::u64;

pub struct BlakeHasher {
    hasher: blake3::Hasher,
}

impl BlakeHasher {
    pub fn new() -> BlakeHasher {
        BlakeHasher {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl Default for BlakeHasher {
    fn default() -> Self {
        BlakeHasher::new()
    }
}

impl Hasher for BlakeHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> () {
        &self.hasher.write(bytes);
    }

    #[inline]
    fn finish(&self) -> u64 {
        let result = self.hasher.finalize();
        let mut hash: [u8; 32] = [0; 32];
        hash.copy_from_slice(result.as_bytes());
        let hash = Hash(hash).to_short();

        decode_le_u64!(&hash.0).unwrap()
    }
}

impl Algorithm<Hash> for BlakeHasher {
    #[inline]
    fn hash(&mut self) -> Hash {
        let mut result: [u8; HASH_BYTES] = [0; HASH_BYTES];
        let mut reader = self.hasher.finalize_xof();
        reader.fill(&mut result);
        Hash(result)
    }

    #[inline]
    fn reset(&mut self) {
        self.hasher = blake3::Hasher::new();
    }
}
