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

use crypto::PublicKey;
use rand::Rng;
use quickcheck::Arbitrary;

#[derive(Hash, PartialEq, Eq, Serialize, Deserialize, Clone, Debug, PartialOrd, Ord)]
pub struct NormalAddress(PublicKey);

impl NormalAddress {
    pub const ADDR_TYPE: u8 = 1;

    pub fn from_bytes(bin: &[u8]) -> Result<NormalAddress, &'static str> {
        let addr_type = bin[0];
        
        if bin.len() == 33 && addr_type == Self::ADDR_TYPE {
            let (_, tail) = bin.split_at(1);
            let mut pkey = [0; 32];
            pkey.copy_from_slice(&tail);

            Ok(NormalAddress(PublicKey(pkey)))
        } else if addr_type != Self::ADDR_TYPE {
            Err("Bad address type")
        } else {
            Err("Bad address length")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let bytes = (&&self.0).0;

        // Push address type
        result.push(Self::ADDR_TYPE);

        for byte in bytes.iter() {
            result.push(*byte);
        }

        result
    }
}

impl Arbitrary for NormalAddress {
    fn arbitrary<G : quickcheck::Gen>(_g: &mut G) -> NormalAddress {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| {
            rng.gen_range(1, 255)
        }).collect();

        let mut result = [0; 32];
        result.copy_from_slice(&bytes);

        NormalAddress(PublicKey(result))
    }

    fn shrink(&self) -> Box<Iterator<Item=Self>> {
        Box::new( (&(&self.0).0).to_vec().shrink().map(|p| {
            let mut result = [0; 32];
            result.copy_from_slice(&p);
            
            NormalAddress(PublicKey(result))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: NormalAddress) -> bool {
            tx == NormalAddress::from_bytes(&NormalAddress::to_bytes(&tx)).unwrap()
        }
    }
}