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

use quickcheck::Arbitrary;
use rand::Rng;
use rust_sodium::crypto::sign::Signature as PrimitiveSig;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Signature(PrimitiveSig);

impl Signature {
    pub fn new(bin: &[u8]) -> Signature {
        let mut sig = [0; 64];
        sig.copy_from_slice(bin);

        Signature(PrimitiveSig(sig))
    }

    #[inline]
    pub fn inner(&self) -> PrimitiveSig {
        self.0
    }

    #[inline]
    pub fn inner_bytes(&self) -> Vec<u8> {
        (self.0).0.to_vec()
    }

    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        (self.0).0.to_vec()
    }

    #[inline]
    pub fn from_bytes(bin: &[u8]) -> Result<Signature, &'static str> {
        if bin.len() == 64 {
            let mut sig = [0; 64];
            sig.copy_from_slice(bin);

            Ok(Signature(PrimitiveSig(sig)))
        } else {
            Err("Bad signature length")
        }
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0))
    }
}

impl Arbitrary for Signature {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> Signature {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..64).map(|_| rng.gen_range(1, 255)).collect();

        let mut result = [0; 64];
        result.copy_from_slice(&bytes);

        Signature(PrimitiveSig(result))
    }
}
