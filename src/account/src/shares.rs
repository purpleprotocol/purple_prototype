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
use quickcheck::Arbitrary;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Shares {
    issued_shares: u32,
    authorized_shares: u32,
    required_percentile: u8,
}

impl Shares {
    pub fn new(issued_shares: u32, authorized_shares: u32, required_percentile: u8) -> Shares {
        Shares {
            issued_shares: issued_shares,
            authorized_shares: authorized_shares,
            required_percentile: required_percentile
        }
    }

    /// Issues the amount of shares by the given amount.
    ///
    /// This function will panic if the sum of the current
    /// issued shares and the amount to be issued is greater
    /// than the authorized amount.
    pub fn issue_shares(&mut self, amount: u32) {
        if self.issued_shares + amount > self.authorized_shares {
            panic!("Cannot issue more shares than authorized");
        }

        self.issued_shares += amount;
    }

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Shares, &'static str> {
        if bytes.len() == 9 {
            let mut rdr = Cursor::new(bytes.to_vec());
            let required_percentile = if let Ok(result) = rdr.read_u8() {
                result
            } else {
                return Err("Bad required percentile");
            };

            rdr.set_position(1);

            let issued_shares = if let Ok(result) = rdr.read_u32::<BigEndian>() {
                result
            } else {
                return Err("Bad issued shares");
            };

            rdr.set_position(5);

            let authorized_shares = if let Ok(result) = rdr.read_u32::<BigEndian>() {
                result
            } else {
                return Err("Bad authorized shares");
            };

            let shares = Shares {
                required_percentile: required_percentile,
                issued_shares: issued_shares,
                authorized_shares: authorized_shares
            };

            Ok(shares)
        } else {
            Err("Bad shares length")
        }
    }
}

impl Arbitrary for Shares {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Shares {
        Shares {
            issued_shares: Arbitrary::arbitrary(g),
            authorized_shares: Arbitrary::arbitrary(g),
            required_percentile: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Shares) -> bool {
            tx == Shares::from_bytes(&Shares::to_bytes(&tx)).unwrap()
        }
    }
}