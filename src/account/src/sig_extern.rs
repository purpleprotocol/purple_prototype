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

use crypto::Signature;

const SIG_TYPE: u8 = 1;

pub trait SigExtern {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(&[u8]) -> Self; 
}

impl SigExtern for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(65);
        let bytes = &&self.0;

        // Push sig type
        result.push(SIG_TYPE);

        for byte in bytes.iter() {
            result.push(*byte);
        }

        result
    }

    fn from_bytes(bin: &[u8]) -> Signature {
        let mut sig = [0; 64];
        sig.copy_from_slice(bin);

        Signature(sig)
    }
}