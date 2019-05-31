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

use crate::hash::*;
use merkle_light::hash::Algorithm;
use std::default::Default;
use std::hash::Hasher;
use std::u64;

pub struct BlakeHasher {
    buffer: Vec<u8>,
}

impl BlakeHasher {
    pub fn new() -> BlakeHasher {
        BlakeHasher { buffer: Vec::new() }
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
        &self.buffer.append(&mut bytes.to_vec());
    }

    #[inline]
    fn finish(&self) -> u64 {
        let result = hash_slice(&self.buffer);
        let hex_encoded = hex::encode(result);

        u64::from_str_radix(&hex_encoded, 16).unwrap()
    }
}

impl Algorithm<Hash> for BlakeHasher {
    #[inline]
    fn hash(&mut self) -> Hash {
        hash_slice(&self.buffer)
    }

    #[inline]
    fn reset(&mut self) {
        self.buffer = Vec::new();
    }
}
