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

use crate::blake_hasher::BlakeHasher;
use crate::short_hash::ShortHash;
use hashdb::Hasher;
use quickcheck::Arbitrary;
use rand::Rng;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::convert::{AsMut, AsRef};
use std::default::Default;

pub const HASH_BYTES: usize = 32;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Hash(pub [u8; HASH_BYTES]);

impl Hash {
    pub const NULL: Hash = Hash([0; HASH_BYTES]);
    pub const NULL_RLP: Hash = Hash([
        218, 34, 59, 9, 150, 124, 91, 210, 17, 7, 67, 48, 126, 10, 246, 211, 159, 97, 114, 10, 167,
        33, 138, 100, 10, 8, 238, 209, 45, 213, 117, 199,
    ]);

    #[inline]
    /// Converts the `Hash` to an unique integer representation.
    pub fn to_u64(&self) -> u64 {
        let short = self.to_short();
        decode_le_u64!(&short.0).unwrap()
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn random() -> Hash {
        let random_bytes = rand::thread_rng().gen::<[u8; HASH_BYTES]>();
        Hash(random_bytes)
    }

    #[inline]
    /// Converts a 32 byte `Hash` to a 8 bytes `ShortHash`
    pub fn to_short(&self) -> ShortHash {
        ShortHash::from_hash(&self)
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

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Hash({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Encodable for Hash {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append(&self.0.to_vec());
    }
}

impl Decodable for Hash {
    #[inline]
    fn decode(bytes: &Rlp) -> Result<Hash, DecoderError> {
        match bytes.data() {
            Ok(data) => {
                let mut result = [0; HASH_BYTES];
                result.copy_from_slice(data);

                Ok(Hash(result))
            }
            _ => Err(DecoderError::Custom("Invalid rlp data")),
        }
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

#[inline]
pub fn hash_slice(val: &[u8]) -> Hash {
    let mut result: [u8; HASH_BYTES] = [0; HASH_BYTES];
    let mut blake_hasher = blake3::Hasher::new();
    blake_hasher.update(val);
    let mut reader = blake_hasher.finalize_xof();
    reader.fill(&mut result);
    Hash(result)
}

impl Arbitrary for Hash {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> Hash {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen_range(1, 255)).collect();

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
