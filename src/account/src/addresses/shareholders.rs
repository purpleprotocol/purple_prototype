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

use crypto::{ToBase58, FromBase58};
use addresses::NormalAddress;
use rlp::*;
use byteorder::{BigEndian, WriteBytesExt};
use rand::Rng;
use quickcheck::Arbitrary;

#[derive(Hash, PartialEq, Eq, Serialize, Deserialize, Clone, Debug)]
pub struct ShareholdersAddress([u8; 32]);

impl ShareholdersAddress {
    pub const ADDR_TYPE: u8 = 3;

    pub fn new(bytes: [u8; 32]) -> ShareholdersAddress {
        ShareholdersAddress(bytes)
    }

    pub fn to_base58(&self) -> String {
        let bin_addr = &self.to_bytes();
        bin_addr.to_base58()
    }

    pub fn from_base58(input: &str) -> Result<ShareholdersAddress, &'static str> {
        match input.from_base58() {
            Ok(bin) => Self::from_bytes(&bin),
            _       => Err("Invalid base58 string!")
        }
    }

    /// Computes a shareholders address from the public keys of the 
    /// shareholders, the creator address and the creator's current nonce.
    pub fn compute(
        keys: &[NormalAddress], 
        creator_address: NormalAddress, 
        nonce: u64
    ) -> ShareholdersAddress {
        let mut buf: Vec<u8> = Vec::new();
        let mut stream = RlpStream::new_list(keys.len());

        // Encode keys with rlp
        for k in keys {
            stream.append(&k.to_bytes());
        }

        let mut encoded_keys = stream.out();
 
        buf.write_u64::<BigEndian>(nonce).unwrap();
        buf.append(&mut creator_address.to_bytes());
        buf.append(&mut encoded_keys);

        // Hash the buffer
        let hash = crypto::hash_slice(&buf);

        ShareholdersAddress(hash.0)
    }

    pub fn from_bytes(bin: &[u8]) -> Result<ShareholdersAddress, &'static str> {
        let addr_type = bin[0];
        
        if bin.len() == 33 && addr_type == Self::ADDR_TYPE {
            let (_, tail) = bin.split_at(1);
            let mut addr = [0; 32];
            addr.copy_from_slice(&tail);

            Ok(ShareholdersAddress(addr))
        } else if addr_type != Self::ADDR_TYPE {
            Err("Bad address type")
        } else {
            Err("Bad slice length")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let bytes = &&self.0;

        // Push address type
        result.push(Self::ADDR_TYPE);

        for byte in bytes.iter() {
            result.push(*byte);
        }

        result
    }
}


impl Arbitrary for ShareholdersAddress {
    fn arbitrary<G : quickcheck::Gen>(_g: &mut G) -> ShareholdersAddress {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| {
            rng.gen_range(1, 255)
        }).collect();

        let mut result = [0; 32];
        result.copy_from_slice(&bytes);

        ShareholdersAddress(result)
    }

    fn shrink(&self) -> Box<Iterator<Item=Self>> {
        Box::new(self.0.to_vec().shrink().map(|p| {
            let mut result = [0; 32];
            result.copy_from_slice(&p);
            
            ShareholdersAddress(result)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn base58(addr: ShareholdersAddress) -> bool {
            let encoded = addr.to_base58();
            ShareholdersAddress::from_base58(&encoded).unwrap() == addr
        }
        
        fn serialize_deserialize(tx: ShareholdersAddress) -> bool {
            tx == ShareholdersAddress::from_bytes(&ShareholdersAddress::to_bytes(&tx)).unwrap()
        }
    }
}