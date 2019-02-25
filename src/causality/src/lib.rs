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

extern crate itc;
extern crate quickcheck;
extern crate rand;
extern crate serde;

use itc::Stamp as ItcStamp;
use itc::{IntervalTreeClock, LessThanOrEqual};
use quickcheck::Arbitrary;
use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};
use std::str::from_utf8;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub struct Stamp(ItcStamp);

impl Stamp {
    pub fn seed() -> Stamp {
        let seed = ItcStamp::seed();
        Stamp(seed)
    }

    pub fn fork(&self) -> (Stamp, Stamp) {
        let s_intern = &&self.0;
        let (s1, s2) = s_intern.fork();

        (Stamp(s1), Stamp(s2))
    }

    pub fn join(&self, s2: Stamp) -> Stamp {
        let s1_intern = &&self.0;
        let s2_intern = &s2.0;

        let result = s1_intern.join(s2_intern);
        Stamp(result)
    }

    pub fn event(&self) -> Stamp {
        let s_intern = &&self.0;
        let result = s_intern.event();

        Stamp(result)
    }

    pub fn peek(&self) -> Stamp {
        let s_intern = &&self.0;
        let (result, _) = s_intern.peek();

        Stamp(result)
    }

    pub fn happened_before(&self, s2: Stamp) -> bool {
        let s1_intern = &&self.0;
        let s2_intern = &s2.0;

        s1_intern.leq(&s2_intern) && !s2_intern.leq(&s1_intern)
    }

    pub fn happened_after(&self, s2: Stamp) -> bool {
        let s1_intern = &&self.0;
        let s2_intern = &s2.0;

        !s1_intern.leq(&s2_intern) && s2_intern.leq(&s1_intern)
    }

    pub fn concurrent(&self, s2: Stamp) -> bool {
        let s1_intern = &&self.0;
        let s2_intern = &s2.0;

        !s1_intern.leq(&s2_intern) && !s2_intern.leq(&s1_intern)
    }

    pub fn equal(&self, s2: Stamp) -> bool {
        let s1_intern = &&self.0;
        let s2_intern = &s2.0;

        s1_intern.leq(&s2_intern) && s2_intern.leq(&s1_intern)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let formatted = format!("{}", &&self.0);

        for byte in formatted.as_bytes() {
            buffer.push(*byte);
        }

        buffer
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Stamp, &'static str> {
        if let Ok(bin) = from_utf8(bin) {
            match ItcStamp::from_str(bin) {
                Ok(res) => Ok(Stamp(res)),
                Err(_) => Err("Invalid stamp"),
            }
        } else {
            Err("The given bin is not a utf8 valid string")
        }
    }
}

impl Serialize for Stamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let formatted = format!("{}", &&self.0);
        serializer.serialize_str(&formatted)
    }
}

impl<'a> Deserialize<'a> for Stamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        let result: &str = Deserialize::deserialize(deserializer)?;

        match ItcStamp::from_str(result) {
            Ok(res) => Ok(Stamp(res)),
            Err(_) => Err(Error::custom(format!("{} is not a valid stamp", result))),
        }
    }
}

impl Arbitrary for Stamp {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> Stamp {
        let stamp = Stamp::seed();

        // TODO: Make this more random and complex
        stamp.event()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_compares_stamps() {
        let seed = Stamp::seed();
        let (r, l) = seed.fork();
        let l_clone = l.clone();

        assert!(r.equal(l));

        let r1 = r.event();
        let l1 = l_clone.event();
        let r2 = r1.join(l1.peek()).event();
        let r2_clone = r2.clone();

        assert!(r1.concurrent(l1));
        assert!(r2.happened_after(r1.clone()));
        assert!(r1.happened_before(r2_clone));
    }

    #[test]
    fn serialize() {
        let seed = Stamp::seed();
        let serialized = seed.to_bytes();

        if let Ok(deserialized) = Stamp::from_bytes(&serialized) {
            assert_eq!(deserialized, seed);
        } else {
            assert!(false);
        }
    }
}
