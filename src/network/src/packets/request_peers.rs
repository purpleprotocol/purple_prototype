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
use crate::interface::NetworkInterface;
use crate::packet::Packet;
use crate::packets::SendPeers;
use crate::peer::ConnectionType;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use chrono::prelude::*;
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use rand::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestPeers {
    /// The node id of the requester
    node_id: NodeId,

    /// Randomly generated nonce
    nonce: u64,

    /// The number of requested peers
    requested_peers: u8,

    /// Packet signature
    signature: Option<Signature>,
}

impl RequestPeers {
    pub fn new(node_id: NodeId, requested_peers: u8) -> RequestPeers {
        let mut rng = rand::thread_rng();

        RequestPeers {
            node_id: node_id,
            requested_peers,
            nonce: rng.gen(),
            signature: None,
        }
    }
}

impl Packet for RequestPeers {
    const PACKET_TYPE: u8 = 4;

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

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        let mut signature = if let Some(signature) = &self.signature {
            signature.inner_bytes()
        } else {
            panic!("Signature field is missing");
        };

        let node_id = &self.node_id.0;

        // Packet structure:
        // 1) Packet type(4)   - 8bits
        // 2) Requested peers  - 8bits
        // 3) Nonce            - 64bits
        // 4) Node id          - 32byte binary
        // 5) Signature        - 64byte binary
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(self.requested_peers).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&node_id.0);
        buffer.extend_from_slice(&signature);

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

        let requested_peers = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        rdr.set_position(2);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..10).collect();

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

        let packet = RequestPeers {
            node_id,
            nonce,
            requested_peers,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &RequestPeers,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        if !packet.verify_sig() {
            return Err(NetworkErr::BadSignature);
        }

        debug!("Received RequestPeers packet from: {:?}", addr);

        let num_of_peers = packet.requested_peers as usize;
        let our_node_id = network.our_node_id();
        let peers = network.peers();
        let peers = peers.read(); 
        let addresses: Vec<SocketAddr> = peers
            .iter()
            // Don't send the address of the requester
            .filter(|(peer_addr, peer)| {
                peer.id.is_some() && peer.id != Some(packet.node_id.clone()) && *peer_addr != addr
            })
            .take(num_of_peers)
            .map(|(addr, _)| addr)
            .cloned()
            .collect();

        let mut send_peers = SendPeers::new(our_node_id.clone(), addresses, packet.nonce);
        network.send_unsigned::<SendPeers>(addr, &mut send_peers)?;

        Ok(())
    }
}

fn assemble_sign_message(obj: &RequestPeers) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let node_id = (obj.node_id.0).0;

    buf.extend_from_slice(&[RequestPeers::PACKET_TYPE, obj.requested_peers]);
    buf.extend_from_slice(&encode_be_u64!(obj.nonce));
    buf.extend_from_slice(&node_id);
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

        RequestPeers {
            node_id: NodeId(*id.pkey()),
            nonce: Arbitrary::arbitrary(g),
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
            let mut packet = RequestPeers {
                node_id: NodeId(*id.pkey()),
                requested_peers: 10,
                nonce: 343324,
                signature: None,
            };

            packet.sign(&id.skey());
            packet.verify_sig()
        }

    }
}
