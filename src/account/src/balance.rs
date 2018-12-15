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

use regex::Regex;
use std::str;
use rand::Rng;
use quickcheck::Arbitrary;
use rust_decimal::Decimal;
use std::str::FromStr;
use std::ops::{Add, Sub, AddAssign, SubAssign};

lazy_static! {
    static ref PREC0: Regex = Regex::new(r"^[0-9]*$").unwrap();
    static ref PREC2: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,2})?$").unwrap();
    static ref PREC3: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,3})?$").unwrap();
    static ref PREC4: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,4})?$").unwrap();
    static ref PREC5: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,5})?$").unwrap();
    static ref PREC6: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,6})?$").unwrap();
    static ref PREC7: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,7})?$").unwrap();
    static ref PREC8: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,8})?$").unwrap();
    static ref PREC9: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,9})?$").unwrap();
    static ref PREC10: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,10})?$").unwrap();
    static ref PREC11: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,11})?$").unwrap(); 
    static ref PREC12: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,12})?$").unwrap();
    static ref PREC13: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,13})?$").unwrap();
    static ref PREC14: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,14})?$").unwrap();
    static ref PREC15: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,15})?$").unwrap();
    static ref PREC16: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,16})?$").unwrap();
    static ref PREC17: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,17})?$").unwrap();
    static ref PREC18: Regex = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,18})?$").unwrap();
}

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct Balance(Decimal);

impl Balance {
    pub fn validate_smaller_precision(&self, precision: u8) -> bool {
        // Validate balance with corresponding precision
        match precision {
            0  => PREC0.is_match(&self.0.to_string()),
            2  => PREC2.is_match(&self.0.to_string()),
            3  => PREC3.is_match(&self.0.to_string()),
            4  => PREC4.is_match(&self.0.to_string()),
            5  => PREC5.is_match(&self.0.to_string()),
            6  => PREC6.is_match(&self.0.to_string()),
            7  => PREC7.is_match(&self.0.to_string()),
            8  => PREC8.is_match(&self.0.to_string()),
            9  => PREC9.is_match(&self.0.to_string()),
            10 => PREC10.is_match(&self.0.to_string()),
            11 => PREC11.is_match(&self.0.to_string()),
            12 => PREC12.is_match(&self.0.to_string()),
            13 => PREC13.is_match(&self.0.to_string()),
            14 => PREC14.is_match(&self.0.to_string()),
            15 => PREC15.is_match(&self.0.to_string()),
            16 => PREC16.is_match(&self.0.to_string()),
            17 => PREC17.is_match(&self.0.to_string()),
            18 => PREC18.is_match(&self.0.to_string()),
            _  => panic!("Invalid precision! The value must either be 0 or a number between 2 and 18!")
        }
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

    pub fn from_bytes(bin: &[u8]) -> Result<Balance, &'static str> {
        match str::from_utf8(bin) {
            Ok(result) => {
                if PREC0.is_match(result) || PREC18.is_match(result) {
                    Ok(Balance(Decimal::from_str(result).unwrap()))
                } else {
                    Err("Invalid balance")
                }
            },
            Err(_) => {
                Err("Invalid utf8 string given")
            }
        }
    }
}

impl Add for Balance {
    type Output = Balance;

    fn add(self, other: Balance) -> Balance {
        Balance(self.0 + other.0)
    }
}

impl Sub for Balance {
    type Output = Balance;

    fn sub(self, other: Balance) -> Balance {
        Balance(self.0 - other.0)
    }
}

impl AddAssign for Balance {
    fn add_assign(&mut self, other: Balance) {
        *self = Balance(self.0 + other.0);
    }
}

impl SubAssign for Balance {
    fn sub_assign(&mut self, other: Balance) {
        *self = Balance(self.0 - other.0);
    }
}

impl Arbitrary for Balance {
    fn arbitrary<G : quickcheck::Gen>(_g: &mut G) -> Balance {
        let mut rng = rand::thread_rng();
        let num1: u64 = rng.gen_range(1, 99999999999);
        let num2: u64 = rng.gen_range(1, 99999999999);
        let generated_str = format!("{}.{}", num1, num2); 

        let result = Decimal::from_str(&generated_str).unwrap();

        Balance(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds_balances() {
        let b1 = Balance::from_bytes(b"10.0").unwrap();
        let b2 = Balance::from_bytes(b"20.0").unwrap();

        assert_eq!(b1 + b2, Balance::from_bytes(b"30.0").unwrap());
    }

    #[test]
    fn it_subtracts_balances() {
        let b1 = Balance::from_bytes(b"10.0").unwrap();
        let b2 = Balance::from_bytes(b"20.0").unwrap();

        assert_eq!(b2 - b1, Balance::from_bytes(b"10.0").unwrap());
    }

    #[test]
    fn it_add_assigns_balances() {
        let mut b1 = Balance::from_bytes(b"10.0").unwrap();
        let b2 = Balance::from_bytes(b"20.0").unwrap();

        b1 += b2;

        assert_eq!(b1, Balance::from_bytes(b"30.0").unwrap());
    }

    #[test]
    fn it_sub_assigns_balances() {
        let mut b1 = Balance::from_bytes(b"20.0").unwrap();
        let b2 = Balance::from_bytes(b"10.0").unwrap();

        b1 -= b2;

        assert_eq!(b1, Balance::from_bytes(b"10.0").unwrap());
    }

    #[test]
    fn it_accepts_balances() {
        if let Ok(_) = Balance::from_bytes(b"10.432") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_rejects_negative_balances() {
        if let Err(_) = Balance::from_bytes(b"-10.432") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_rejects_balances_with_invalid_characters() {
        if let Err(_) = Balance::from_bytes(b"10.4fds32") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_rejects_balances_with_higher_precision_than_allowed() {
        if let Err(_) = Balance::from_bytes(b"10.0000000000000000001") {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn it_accepts_balances_with_maximum_allowed_precision() {
        if let Err(_) = Balance::from_bytes(b"10.000000000000000001") {
            assert!(false);
        } else {
            assert!(true);
        }
    }
}