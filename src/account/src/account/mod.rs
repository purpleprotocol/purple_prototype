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

pub mod normal;
pub mod multi_sig;
pub mod shareholders;
pub mod contract;

use account::contract::*;
use account::normal::*;
use account::multi_sig::*;
use account::shareholders::*;

#[derive(Clone, Debug)]
pub enum Account {
    Normal(Normal),
    Contract(Contract),
    MultiSig(MultiSig),
    Shareholders(Shareholders)
}

impl Account {
    pub fn from_bytes(bytes: &[u8]) -> Result<Account, &'static str> {
        let first_byte = bytes[0];

        match first_byte {
            1 => match Normal::from_bytes(bytes) {
                Ok(result) => Ok(Account::Normal(result)),
                Err(err)   => Err(err)
            },
            2 => match Contract::from_bytes(bytes) {
                Ok(result) => Ok(Account::Contract(result)),
                Err(err)   => Err(err)
            },
            3 => match MultiSig::from_bytes(bytes) {
                Ok(result) => Ok(Account::MultiSig(result)),
                Err(err)   => Err(err)
            },
            4 => match Shareholders::from_bytes(bytes) {
                Ok(result) => Ok(Account::Shareholders(result)),
                Err(err)   => Err(err)
            },
            _ => Err("Invalid first byte!")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Account::Normal(ref acc)       => acc.to_bytes(),
            Account::Contract(ref acc)     => acc.to_bytes(),
            Account::MultiSig(ref acc)     => acc.to_bytes(),
            Account::Shareholders(ref acc) => acc.to_bytes()
        }
    }
}
