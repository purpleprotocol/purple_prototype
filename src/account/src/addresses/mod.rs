/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

pub mod contract;
pub mod normal;

use addresses::contract::*;
use addresses::normal::*;
use crypto::PublicKey;
use std::fmt;

#[derive(Hash, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Address {
    Normal(NormalAddress),
    Contract(ContractAddress),
}

impl Address {
    /// Unwraps an `Address` enum into a normal address.
    ///
    /// This function panics if the enum variant isn't a `NormalAddress`.
    pub fn unwrap_normal(&self) -> NormalAddress {
        match *self {
            Address::Normal(ref addr) => *addr,
            _ => panic!("Unwrap normal called on a non normal address"),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Address::Normal(ref addr) => addr.to_bytes(),
            Address::Contract(ref addr) => addr.to_bytes(),
        }
    }
    pub fn normal_from_pkey(pkey: PublicKey) -> Address {
        Address::Normal(NormalAddress::from_pkey(pkey))
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Address, &'static str> {
        let addr_type = bin[0];

        match addr_type {
            1 => match NormalAddress::from_bytes(bin) {
                Ok(result) => Ok(Address::Normal(result)),
                Err(err) => Err(err),
            },
            2 => match ContractAddress::from_bytes(bin) {
                Ok(result) => Ok(Address::Contract(result)),
                Err(err) => Err(err),
            },
            _ => Err("Bad address type!"),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Address::Normal(ref addr) => write!(f, "{}", addr),
            Address::Contract(ref addr) => write!(f, "{}", addr),
        }
    }
}

use quickcheck::Arbitrary;
use rand::Rng;

impl Arbitrary for Address {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Address {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(1, 3);

        match random {
            1 => Address::Normal(Arbitrary::arbitrary(g)),
            2 => Address::Contract(Arbitrary::arbitrary(g)),
            _ => panic!(),
        }
    }
}
