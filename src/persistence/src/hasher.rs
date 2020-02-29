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

use crc64fast::Digest;
use crypto::{BlakeHasher, ShortHash, SHORT_HASH_BYTES};
use hashdb::Hasher;

pub struct DbHasher;

impl Hasher for DbHasher {
    const LENGTH: usize = SHORT_HASH_BYTES;

    type Out = ShortHash;
    type StdHasher = BlakeHasher;

    fn hash(bytes: &[u8]) -> Self::Out {
        let mut c = Digest::new();
        c.write(bytes);
        let checksum = c.sum64();
        let checksum = encode_le_u64!(checksum);
        let mut hash_bytes = [0; SHORT_HASH_BYTES];
        hash_bytes.copy_from_slice(&checksum);

        ShortHash(hash_bytes)
    }
}
