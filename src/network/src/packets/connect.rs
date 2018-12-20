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

use crypto::{Signature, PublicKey as Pk, SecretKey as Sk};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq)]
pub struct Connect {
    node_id: Pk,
    kx_key: Pk,
    signature: Option<Signature>
}

impl Connect {
    pub const PACKET_TYPE: u8 = 1;

    pub fn new(node_id: Pk, kx_key: Pk) -> Connect {
        Connect {
            node_id: node_id,
            kx_key: kx_key,
            signature: None
        }
    }

    pub fn sign(&mut self, skey: Sk) {
        unimplemented!();
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(129);
        let packet_type: u8 = Self::PACKET_TYPE;

        let mut signature = if let Some(signature) = &self.signature {
            signature.inner_bytes()
        } else {
            panic!("Signature field is missing");
        };

        let node_id = &self.node_id.0;
        let kx_key = &self.kx_key.0;

        // Connect packet structure:
        // 1) Packet type(1)   - 8bits
        // 2) Key exchange pk  - 32byte binary
        // 3) Node id          - 32byte binary
        // 4) Signature        - 64byte binary
        buffer.write_u8(packet_type).unwrap();
        buffer.append(&mut kx_key.to_vec());
        buffer.append(&mut node_id.to_vec());
        buffer.append(&mut signature);

        buffer
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Connect, &'static str> {
        let mut rdr = Cursor::new(bin.to_vec());
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad packet type");
        };

        if packet_type != Self::PACKET_TYPE {
            return Err("Bad packet type");
        }

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..1).collect();

        let kx_key = if buf.len() > 32 as usize {
            let kx_key_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&kx_key_vec);

            Pk(b)
        } else {
            return Err("Incorrect packet structure");
        };

        let node_id = if buf.len() > 32 as usize {
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&node_id_vec);

            Pk(b)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() == 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();
            Signature::new(&sig_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let packet = Connect {
            node_id: node_id,
            kx_key: kx_key,
            signature: Some(signature)
        };

        Ok(packet)
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for Connect {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Connect {
        let id1 = Identity::new();
        let id2 = Identity::new();
        
        Connect {
            node_id: *id1.pkey(),
            kx_key: *id2.pkey(),
            signature: Some(Arbitrary::arbitrary(g))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Connect) -> bool {
            tx == Connect::from_bytes(&Connect::to_bytes(&tx)).unwrap()
        }
    }
}