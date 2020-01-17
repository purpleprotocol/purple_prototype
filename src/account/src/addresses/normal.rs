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

use crypto::{FromBase58, PublicKey, Hash, ToBase58};
use quickcheck::Arbitrary;
use rand::Rng;
use std::fmt;
use std::hash::{Hash as HashTrait, Hasher};

#[derive(Copy, Clone)]
pub struct NormalAddress([u8; 33]);

impl NormalAddress {
    pub const ADDR_TYPE: u8 = 1;

    pub fn to_base58(&self) -> String {
        self.0.to_base58()
    }

    pub fn from_base58(input: &str) -> Result<NormalAddress, &'static str> {
        match input.from_base58() {
            Ok(bin) => Self::from_bytes(&bin),
            _ => Err("Invalid base58 string!"),
        }
    }

    pub fn random() -> NormalAddress {
        let (pk, _) = crypto::gen_keypair();
        NormalAddress::from_pkey(&pk)
    }

    pub fn from_pkey(pkey: &PublicKey) -> NormalAddress {
        let pk_bytes = &pkey.0;
        let pkey_hash = crypto::hash_slice(pk_bytes);
        let mut addr_bytes = [0; 33];
        let mut idx = 1;
        
        addr_bytes[0] = Self::ADDR_TYPE;

        for byte in &pkey_hash.0 {
            addr_bytes[idx] = *byte;
            idx += 1;
        }

        NormalAddress(addr_bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bin: &[u8]) -> Result<NormalAddress, &'static str> {
        let addr_type = bin[0];

        if bin.len() == 33 && addr_type == Self::ADDR_TYPE {
            let mut bytes = [0; 33];
            bytes.copy_from_slice(&bin);

            Ok(NormalAddress(bytes))
        } else if addr_type != Self::ADDR_TYPE {
            Err("Bad address type")
        } else {
            Err("Bad address length")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

fn unsize<T>(x: &[T]) -> &[T] { x }

impl PartialEq for NormalAddress {
    fn eq(&self, other: &NormalAddress) -> bool {
        unsize(&self.0) == unsize(&other.0)
    }
}

impl Eq for NormalAddress { }

impl HashTrait for NormalAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for NormalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl fmt::Display for NormalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl Arbitrary for NormalAddress {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> NormalAddress {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen_range(1, 255)).collect();

        let mut addr_bytes = [0; 33];
        let mut idx = 1;
        
        addr_bytes[0] = Self::ADDR_TYPE;

        for byte in &bytes {
            addr_bytes[idx] = *byte;
            idx += 1;
        }

        NormalAddress(addr_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn base58(addr: NormalAddress) -> bool {
            let encoded = addr.to_base58();
            NormalAddress::from_base58(&encoded).unwrap() == addr
        }

        fn serialize_deserialize(addr: NormalAddress) -> bool {
            addr == NormalAddress::from_bytes(&NormalAddress::to_bytes(&addr)).unwrap()
        }
    }
}
