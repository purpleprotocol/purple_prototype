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
use SigExtern;

#[derive(Serialize, Deserialize, Debug)]
pub struct MultiSig(Vec<Signature>);

impl MultiSig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(self.0.len());
        
        for sig in self.0.iter() {
            sigs.push(sig.to_bytes());
        }

        let result: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&sigs);

        result
    }
}