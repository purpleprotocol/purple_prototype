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

use crate::hash::Hash;
use crc32fast::Hasher as CrcHasher;
use quickcheck::Arbitrary;
use rand::Rng;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::default::Default;

pub const SHORT_HASH_BYTES: usize = 8;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
/// A short (8bytes) representation of a `Hash` which has 32 bytes.
pub struct ShortHash(pub [u8; SHORT_HASH_BYTES]);

impl ShortHash {
    pub const NULL: ShortHash = ShortHash([0; SHORT_HASH_BYTES]);
    pub const NULL_RLP: ShortHash = ShortHash([27, 48, 224, 179, 230, 246, 193, 214]);

    #[inline]
    pub fn from_hash(hash: &Hash) -> ShortHash {
        let mut short_hash = [0; SHORT_HASH_BYTES];
        let short_bytes = &hash.0[..SHORT_HASH_BYTES];

        short_hash.copy_from_slice(short_bytes);
        ShortHash(short_hash)
    }

    #[inline]
    /// Converts the `ShortHash` to an unique integer representation.
    pub fn to_u64(&self) -> u64 {
        decode_le_u64!(&self.0).unwrap()
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
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

impl Encodable for ShortHash {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append(&self.0.to_vec());
    }
}

impl Decodable for ShortHash {
    #[inline]
    fn decode(bytes: &Rlp) -> Result<ShortHash, DecoderError> {
        match bytes.data() {
            Ok(data) => {
                let mut result = [0; SHORT_HASH_BYTES];
                result.copy_from_slice(data);

                Ok(ShortHash(result))
            }
            _ => Err(DecoderError::Custom("Invalid rlp data")),
        }
    }
}

impl AsMut<[u8]> for ShortHash {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl AsRef<[u8]> for ShortHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Arbitrary for ShortHash {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> ShortHash {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..SHORT_HASH_BYTES)
            .map(|_| rng.gen_range(1, 255))
            .collect();

        let mut result = [0; SHORT_HASH_BYTES];
        result.copy_from_slice(&bytes);

        ShortHash(result)
    }
}
