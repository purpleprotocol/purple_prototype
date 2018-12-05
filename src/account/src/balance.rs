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

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct Balance(Decimal);

impl Balance {
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
        let rgx = Regex::new(r"^[0-9]{1,18}([.][0-9]{1,18})?$").unwrap();

        match str::from_utf8(bin) {
            Ok(result) => {
                if rgx.is_match(result) {
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
}