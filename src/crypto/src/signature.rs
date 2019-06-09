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

use quickcheck::Arbitrary;
use rand::Rng;
use ed25519_dalek::Signature as PrimitiveSig;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Signature(pub(crate) PrimitiveSig);

impl Signature {
    pub fn new(bin: &[u8]) -> Signature {
        Signature(PrimitiveSig::from_bytes(bin).unwrap())
    }

    pub fn inner(&self) -> PrimitiveSig {
        self.0
    }

    pub fn inner_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Signature, &'static str> {
        if bin.len() == 64 {
            match PrimitiveSig::from_bytes(&bin) {
                Ok(result) => Ok(Signature(result)),
                _ => Err("Bad signature")
            }
        } else {
            Err("Bad signature length")
        }
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0.to_bytes().to_vec()))
    }
}

impl Arbitrary for Signature {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Signature {
        let id = crate::Identity::new();
        let message: Vec<u8> = Arbitrary::arbitrary(g);
        crate::sign(&message, id.skey(), id.pkey())
    }
}
