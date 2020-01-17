/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

use regex::Regex;
use rust_decimal::Decimal;
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::str;
use std::str::FromStr;

lazy_static! {
    static ref PREC18: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,18})?$").unwrap();
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize, Clone, Debug)]
pub struct Gas(Decimal);

impl Gas {
    pub fn to_inner(&self) -> Decimal {
        self.0.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let formatted = format!("{}", &self.0);
        let bytes = formatted.as_bytes();

        for byte in bytes.iter() {
            result.push(*byte);
        }

        result
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Gas, &'static str> {
        match str::from_utf8(bin) {
            Ok(result) => {
                if PREC18.is_match(result) {
                    Ok(Gas(Decimal::from_str(result).unwrap()))
                } else {
                    Err("Invalid gas")
                }
            }
            Err(_) => Err("Invalid utf8 string given"),
        }
    }
}

impl fmt::Display for Gas {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for Gas {
    type Output = Gas;

    fn add(self, other: Gas) -> Gas {
        Gas(self.0 + other.0)
    }
}

impl Sub for Gas {
    type Output = Gas;

    fn sub(self, other: Gas) -> Gas {
        Gas(self.0 - other.0)
    }
}

impl AddAssign for Gas {
    fn add_assign(&mut self, other: Gas) {
        *self = Gas(self.0 + other.0);
    }
}

impl SubAssign for Gas {
    fn sub_assign(&mut self, other: Gas) {
        *self = Gas(self.0 - other.0);
    }
}

use quickcheck::Arbitrary;
use rand::Rng;

impl Arbitrary for Gas {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> Gas {
        let mut rng = rand::thread_rng();
        let num1: u64 = rng.gen_range(1, 99999999999);
        let num2: u64 = rng.gen_range(1, 99999999999);
        let generated_str = format!("{}.{}", num1, num2);

        let result = Decimal::from_str(&generated_str).unwrap();

        Gas(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds_balances() {
        let b1 = Gas::from_bytes(b"10.0").unwrap();
        let b2 = Gas::from_bytes(b"20.0").unwrap();

        assert_eq!(b1 + b2, Gas::from_bytes(b"30.0").unwrap());
    }

    #[test]
    fn it_subtracts_balances() {
        let b1 = Gas::from_bytes(b"10.0").unwrap();
        let b2 = Gas::from_bytes(b"20.0").unwrap();

        assert_eq!(b2 - b1, Gas::from_bytes(b"10.0").unwrap());
    }

    #[test]
    fn it_add_assigns_balances() {
        let mut b1 = Gas::from_bytes(b"10.0").unwrap();
        let b2 = Gas::from_bytes(b"20.0").unwrap();

        b1 += b2;

        assert_eq!(b1, Gas::from_bytes(b"30.0").unwrap());
    }

    #[test]
    fn it_sub_assigns_balances() {
        let mut b1 = Gas::from_bytes(b"20.0").unwrap();
        let b2 = Gas::from_bytes(b"10.0").unwrap();

        b1 -= b2;

        assert_eq!(b1, Gas::from_bytes(b"10.0").unwrap());
    }

    #[test]
    fn it_accepts_balances() {
        if let Ok(_) = Gas::from_bytes(b"10.432") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_rejects_negative_balances() {
        if let Err(_) = Gas::from_bytes(b"-10.432") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_rejects_balances_with_invalid_characters() {
        if let Err(_) = Gas::from_bytes(b"10.4fds32") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_rejects_balances_with_higher_precision_than_allowed() {
        if let Err(_) = Gas::from_bytes(b"10.0000000000000000001") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_accepts_balances_with_maximum_allowed_precision() {
        if let Err(_) = Gas::from_bytes(b"10.000000000000000001") {
            assert!(false);
        } else {
            assert!(true);
        }
    }

    quickcheck! {
        fn serialize_deserialize(b: Gas) -> bool {
            b == Gas::from_bytes(&Gas::to_bytes(&b)).unwrap()
        }
    }
}
