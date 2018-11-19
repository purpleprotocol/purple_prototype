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

#[derive(Serialize, Deserialize, Debug)]
pub struct Balance(String);

impl Balance {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let bytes = &self.0.as_bytes();

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
                    Ok(Balance(result.to_string()))
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