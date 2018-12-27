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

use rust_sodium::crypto::sign::Signature as PrimitiveSig;
use rand::Rng;
use quickcheck::Arbitrary;

const SIG_TYPE: u8 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Signature(PrimitiveSig);

impl Signature {
    pub fn new(bin: &[u8]) -> Signature {
        let mut sig = [0; 64];
        sig.copy_from_slice(bin);

        Signature(PrimitiveSig(sig))
    }

    pub fn inner(&self) -> PrimitiveSig {
        self.0
    }

    pub fn inner_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(64);
        let bytes = &&(&self.0).0;

        for byte in bytes.iter() {
            result.push(*byte);
        }

        result 
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(65);
        let bytes = &&(&self.0).0;

        // Push sig type
        result.push(SIG_TYPE);

        for byte in bytes.iter() {
            result.push(*byte);
        }

        result
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Signature, &'static str> {
        if bin.len() == 65 {
            let (_, tail) = bin.split_at(1);
            let mut sig = [0; 64];
            sig.copy_from_slice(tail);

            Ok(Signature(PrimitiveSig(sig)))
        } else {
            Err("Bad signature length")
        }
    }
}

impl Arbitrary for Signature {
    fn arbitrary<G : quickcheck::Gen>(_g: &mut G) -> Signature {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..64).map(|_| {
            rng.gen_range(1, 255)
        }).collect();

        let mut result = [0; 64];
        result.copy_from_slice(&bytes);

        Signature(PrimitiveSig(result))
    }
}