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

use crate::error::NetworkErr;
use crate::packet::Packet;
use crate::interface::NetworkInterface;
use crate::peer::ConnectionType;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use chrono::prelude::*;
use crypto::{PublicKey as Pk, SecretKey as Sk, NodeId, Signature};
use std::net::SocketAddr;
use std::sync::Arc;
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq)]
pub struct Pong {
    node_id: NodeId,
    nonce: u64,
    signature: Option<Signature>,
}

impl Pong {
    pub fn new(node_id: NodeId, nonce: u64) -> Pong {
        Pong {
            node_id: node_id,
            nonce,
            signature: None,
        }
    }
}

impl Packet for Pong {
    const PACKET_TYPE: u8 = 3;

    fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    fn verify_sig(&self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.node_id.0),
            None => false,
        }
    }

    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &Pong,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let signature = if let Some(signature) = &self.signature {
            signature.inner_bytes()
        } else {
            panic!("Signature field is missing");
        };

        let node_id = &self.node_id.0;

        // Pong packet structure:
        // 1) Packet type(3)   - 8bits
        // 2) Nonce            - 64bits
        // 3) Node id          - 32byte binary
        // 4) Signature        - 64byte binary
        buffer.write_u8(Self::PACKET_TYPE).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&node_id.0);
        buffer.extend_from_slice(&signature);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<Pong>, NetworkErr> {
        let mut rdr = Cursor::new(bin.to_vec());
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if packet_type != Self::PACKET_TYPE {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(1);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..9).collect();

        let node_id = if buf.len() > 32 as usize {
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&node_id_vec);

            NodeId(Pk(b))
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let signature = if buf.len() == 64 as usize {
            Signature::new(&buf)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = Pong {
            node_id,
            nonce,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }
}

fn assemble_message(obj: &Pong) -> Vec<u8> {
    let node_id = (obj.node_id.0).0;
    let mut buf: Vec<u8> = Vec::with_capacity(1 + 32 + 8);

    buf.extend_from_slice(&[Pong::PACKET_TYPE]);
    buf.extend_from_slice(&encode_be_u64!(obj.nonce));
    buf.extend_from_slice(&node_id);
    buf
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for Pong {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Pong {
        let id = Identity::new();

        Pong {
            node_id: NodeId(*id.pkey()),
            nonce: Arbitrary::arbitrary(g),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<Pong>) -> bool {
            packet == Pong::from_bytes(&Pong::to_bytes(&packet)).unwrap()
        }
    }
}