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

use crypto::Signature as PrimitiveSig;
use MultiSig;
use SigExtern;

#[derive(Serialize, Deserialize, Debug)]
pub enum Signature {
    Normal(PrimitiveSig),
    MultiSig(MultiSig),
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Signature::Normal(ref sig)   => sig.to_bytes(),
            Signature::MultiSig(ref sig) => sig.to_bytes()
        }
    }
}