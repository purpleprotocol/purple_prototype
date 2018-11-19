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

use Address;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use quickcheck::Arbitrary;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareMap(HashMap<Address, u32>);

impl ShareMap {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<Vec<u8>> = Vec::with_capacity(self.0.len());
        
        for (k, v) in self.0.iter() {
            let mut b: Vec<u8> = Vec::with_capacity(36);
            let mut k = k.to_bytes();

            // Fields:
            // 1) Shares       - 32bits
            // 2) Shareholder  - 32byte binary
            b.write_u32::<BigEndian>(*v).unwrap();
            b.append(&mut k);

            buf.push(b);
        }

        rlp::encode_list::<Vec<u8>, _>(&buf)
    }
}

impl Arbitrary for ShareMap {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> ShareMap {
        let share_map: HashMap<Address, u32> = Arbitrary::arbitrary(g);
        ShareMap(share_map)
    }
}