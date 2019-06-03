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

use std::fmt;
use std::ops::{Add, AddAssign};
use std::hash::{Hash, Hasher};
use multi_sigs::bls::common::VerKey;
use multi_sigs::bls::types::GroupG2;

#[derive(Clone)]
pub struct BlsPkey(pub VerKey);

impl Add for BlsPkey {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut point: GroupG2 = GroupG2::new();
        point.inf();
        point.add(&self.0.point);
        point.add(&other.0.point);

        BlsPkey(VerKey { point })
    }   
}

impl AddAssign for BlsPkey {
    fn add_assign(&mut self, other: Self) {
        let mut point: GroupG2 = GroupG2::new();
        point.inf();
        point.add(&self.0.point);
        point.add(&other.0.point);

        *self = BlsPkey(VerKey { point });
    }
}

impl PartialEq for BlsPkey {
    fn eq(&self, other: &Self) -> bool {
        crate::hash_slice(&self.0.to_bytes()) == crate::hash_slice(&other.0.to_bytes())
    }
}

impl Eq for BlsPkey { }

impl fmt::Debug for BlsPkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlsPkey({})", hex::encode(self.0.to_bytes()))
    }
}

impl Hash for BlsPkey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl BlsPkey {
    pub fn new(key: VerKey) -> BlsPkey {
        BlsPkey(key)
    }
}