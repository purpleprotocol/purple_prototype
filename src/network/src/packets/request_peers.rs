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

use crate::peer::ConnectionType;
use crate::interface::NetworkInterface;
use crate::node_id::NodeId;
use crate::error::NetworkErr;
use crate::packet::Packet;
use chrono::prelude::*;
use std::sync::Arc;
use std::net::SocketAddr;
use std::str;
use std::io::Cursor;
use byteorder::{ReadBytesExt, WriteBytesExt};
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};

#[derive(Debug, Clone, PartialEq)]
pub struct RequestPeers {
    /// The node id of the requester
    node_id: NodeId,

    /// The packet's timestamp
    timestamp: DateTime<Utc>,

    /// The number of requested peers
    requested_peers: u8,

    /// Packet signature
    signature: Option<Signature>
}

impl RequestPeers {
    pub const PACKET_TYPE: u8 = 2;

    pub fn new(node_id: NodeId, requested_peers: u8) -> RequestPeers {
        RequestPeers {
            node_id: node_id,
            requested_peers,
            timestamp: Utc::now(),
            signature: None,
        }
    }
}

impl Packet for RequestPeers {
    fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    fn verify_sig(&self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.node_id.0),
            None => false,
        }
    }

    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        let mut signature = if let Some(signature) = &self.signature {
            signature.inner_bytes()
        } else {
            panic!("Signature field is missing");
        };

        let timestamp = self.timestamp().to_rfc3339();
        let timestamp_length = timestamp.len() as u8;
        let node_id = &self.node_id.0;

        // Connect packet structure:
        // 1) Packet type(2)   - 8bits
        // 2) Timestamp length - 8bits
        // 3) Requested peers  - 8bits
        // 4) Node id          - 32byte binary
        // 5) Signature        - 64byte binary
        // 6) Timestamp        - Binary of timestamp length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(timestamp_length).unwrap();
        buffer.write_u8(self.requested_peers).unwrap();
        buffer.extend_from_slice(&node_id.0);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(timestamp.as_bytes());

        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<RequestPeers>, NetworkErr> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if packet_type != Self::PACKET_TYPE {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(1);

        let timestamp_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        rdr.set_position(2);

        let requested_peers = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..3).collect();

        let node_id = if buf.len() > 32 as usize {
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&node_id_vec);

            NodeId(Pk(b))
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();
            Signature::new(&sig_vec)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let timestamp = if buf.len() == timestamp_len as usize {
            let result: Vec<u8> = buf.drain(..timestamp_len as usize).collect();
            
            match str::from_utf8(&result) {
                Ok(result) => match DateTime::parse_from_rfc3339(result) {
                    Ok(result) => Utc.from_utc_datetime(&result.naive_utc()),
                    _ => return Err(NetworkErr::BadFormat)
                },
                Err(_) => return Err(NetworkErr::BadFormat)
            } 
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = RequestPeers {
            node_id,
            timestamp,
            requested_peers,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(network: &mut N, addr: &SocketAddr, packet: &RequestPeers, conn_type: ConnectionType) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

fn assemble_sign_message(obj: &RequestPeers) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let node_id = (obj.node_id.0).0;
    let timestamp = obj.timestamp.to_rfc3339();

    buf.extend_from_slice(&[RequestPeers::PACKET_TYPE, obj.requested_peers]);
    buf.extend_from_slice(&node_id);
    buf.extend_from_slice(timestamp.as_bytes());

    buf
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for RequestPeers {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RequestPeers {
        let id = Identity::new();
        let timestamp = Utc::now();

        RequestPeers {
            node_id: NodeId(*id.pkey()),
            timestamp,
            requested_peers: Arbitrary::arbitrary(g),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<RequestPeers>) -> bool {
            tx == RequestPeers::from_bytes(&RequestPeers::to_bytes(&tx)).unwrap()
        }

        fn verify_signature(id1: Identity, id2: Identity) -> bool {
            let id = Identity::new();
            let timestamp = Utc::now();
            let mut packet = RequestPeers {
                node_id: NodeId(*id.pkey()),
                requested_peers: 10,
                signature: None,
                timestamp
            };

            packet.sign(&id.skey());
            packet.verify_sig()
        }

    }
}
