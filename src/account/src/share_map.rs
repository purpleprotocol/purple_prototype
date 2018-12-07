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

use crypto::Signature;
use addresses::normal::NormalAddress;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use quickcheck::Arbitrary;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareMap {
    share_map: HashMap<NormalAddress, u64>,
    issued_shares: u64
}

impl ShareMap {
    pub fn new() -> ShareMap {
        ShareMap {
            share_map: HashMap::new(),
            issued_shares: 0
        }
    }

    pub fn add_shareholder(&mut self, addr: NormalAddress, shares: u64) {
        self.share_map.insert(addr, shares);
        self.issued_shares += shares;
    }

    /// Given a message and a signature, attempts to find a
    /// shareholder whose public key has successfuly verifies
    /// the signature.
    ///
    /// If a match is found, this function will return the owned
    /// ratio of shares of the signer.
    ///
    /// Returns `None` if no match is found.
    pub fn find_signer(&self, message: &[u8], signature: Signature) -> Option<u8> {
        let mut result: Option<u8> = None;

        // Attempt to find a matching key
        for (addr, shares) in self.share_map.iter() {
            if crypto::verify(message, signature.clone(), addr.pkey()) {
                // A match has been found
                let signer_ratio: u8 = (self.issued_shares / (*shares as u64) * 100) as u8;
                
                result = Some(signer_ratio);
                break;
            }
        }

        result
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<Vec<u8>> = Vec::with_capacity(self.share_map.len());
        
        for (k, v) in self.share_map.iter() {
            let mut b: Vec<u8> = Vec::with_capacity(36);
            let mut k = k.to_bytes();

            // Fields:
            // 1) Shares       - 64bits
            // 2) Shareholder  - 33byte binary
            b.write_u64::<BigEndian>(*v).unwrap();
            b.append(&mut k);

            buf.push(b);
        }

        rlp::encode_list::<Vec<u8>, _>(&buf)
    }

    pub fn from_bytes(bin: &[u8]) -> Result<ShareMap, &'static str> {
        let mut buf: HashMap<NormalAddress, u64> = HashMap::new();
        let decoded: Vec<Vec<u8>> = rlp::decode_list(bin);
        let mut issued_shares: u64 = 0;

        for bytes in decoded {
            if bytes.len() == 41 {
                let mut rdr = Cursor::new(bytes);
                let shares = if let Ok(result) = rdr.read_u64::<BigEndian>() {
                    result
                } else {
                    return Err("Bad shares");
                };

                let mut b = rdr.into_inner();
                let _: Vec<u8> = b.drain(..8).collect();

                let address_vec: Vec<u8> = b.drain(..33).collect();

                match NormalAddress::from_bytes(&address_vec) {
                    Ok(address) => {
                        issued_shares += shares;
                        buf.insert(address, shares)
                    },
                    Err(err) => return Err(err)
                };
            } else {
                return Err("Bad address");
            }
        }

        let share_map = ShareMap {
            share_map: buf,
            issued_shares: issued_shares
        };

        Ok(share_map)
    }
}

impl Arbitrary for ShareMap {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> ShareMap {
        let sm: HashMap<NormalAddress, u64> = Arbitrary::arbitrary(g);
        let mut shares: u64 = 0;

        for (_, v) in sm.iter() {
            shares += v;
        } 

        ShareMap {
            share_map: sm,
            issued_shares: shares
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: ShareMap) -> bool {
            tx == ShareMap::from_bytes(&ShareMap::to_bytes(&tx)).unwrap()
        }
    }
}