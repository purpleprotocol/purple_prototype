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

use crypto::{FromBase58, PublicKey, Hash, ToBase58};
use quickcheck::Arbitrary;
use rand::Rng;
use std::fmt;

#[derive(Hash, Copy, PartialEq, Eq, Serialize, Deserialize, Clone, Debug, PartialOrd, Ord)]
pub struct NormalAddress(Hash);

impl NormalAddress {
    pub const ADDR_TYPE: u8 = 1;

    pub fn to_base58(&self) -> String {
        self.to_bytes().to_base58()
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
        NormalAddress(pkey_hash)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &(self.0).0
    }

    pub fn from_bytes(bin: &[u8]) -> Result<NormalAddress, &'static str> {
        let addr_type = bin[0];

        if bin.len() == 33 && addr_type == Self::ADDR_TYPE {
            let (_, tail) = bin.split_at(1);
            let mut hash = [0; 32];
            hash.copy_from_slice(&tail);

            Ok(NormalAddress(Hash(hash)))
        } else if addr_type != Self::ADDR_TYPE {
            Err("Bad address type")
        } else {
            Err("Bad address length")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(33);
        let bytes = (self.0).0;

        // Push address type
        result.push(Self::ADDR_TYPE);

        for byte in bytes.iter() {
            result.push(*byte);
        }

        result
    }
}

impl fmt::Display for NormalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl Arbitrary for NormalAddress {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> NormalAddress {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen_range(1, 255)).collect();

        let mut result = [0; 32];
        result.copy_from_slice(&bytes);

        NormalAddress(Hash(result))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new((&(&self.0).0).to_vec().shrink().map(|p| {
            let mut result = [0; 32];
            result.copy_from_slice(&p);

            NormalAddress(Hash(result))
        }))
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
