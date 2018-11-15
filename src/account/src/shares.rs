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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[derive(Serialize, Deserialize, Debug)]
pub struct Shares {
    issued_shares: u32,
    authorized_shares: u32,
    required_percentile: u8,
}

impl Shares {
    /// Fields:
    /// 1) Required percentile   - 8bits
    /// 2) Issued shares         - 32bits
    /// 3) Authorized shares     - 32bits
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(9);
        let issued_shares = &self.issued_shares;
        let authorized_shares = &self.authorized_shares;
        let required_percentile = &self.required_percentile;

        buf.write_u8(*required_percentile).unwrap();
        buf.write_u32::<BigEndian>(*issued_shares).unwrap();
        buf.write_u32::<BigEndian>(*authorized_shares).unwrap();
        
        buf
    }
}
