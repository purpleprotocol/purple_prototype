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

extern crate crypto;

use crypto::*;

extern "C" {
    fn JumpConsistentHash(key: u64, num: i32) -> i32;
}

pub fn jump_bytes(key: &[u8], buckets: i32) -> i32 {
    let key_hash: Vec<u8> = hash_slice(key).to_vec();
    let key: u64 = bytes_to_uint(&key_hash);

    jump_ch(key, buckets)
}

pub fn jump_ch(key: u64, buckets: i32) -> i32 {
    unsafe { JumpConsistentHash(key, buckets) }
}

// Convert bytes to uint assuming they are in big endian order
fn bytes_to_uint(bin: &[u8]) -> u64 {
    let mut result: u64 = 0;

    for byte in bin {
        result = result.wrapping_shl(8).wrapping_add((byte & 0xff) as u64);
    }

    result
}

#[test]
fn jump_bytes_test() {
    let key = b"The quick brown fox jumps over the lazy dog";
    let hash = hash_slice(key).to_vec();
    let key_uint = bytes_to_uint(&hash);

    let result1 = jump_bytes(key, 10);
    let result2 = jump_ch(key_uint, 10);

    assert_eq!(result1, result2);
}
