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
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use rand::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestPeers {
    /// Randomly generated nonce
    nonce: u64,

    /// The number of requested peers
    requested_peers: u8,
}

impl RequestPeers {
    pub fn new(requested_peers: u8) -> RequestPeers {
        let mut rng = rand::thread_rng();

        RequestPeers {
            requested_peers,
            nonce: rng.gen(),
        }
    }
}

impl Packet for RequestPeers {
    const PACKET_TYPE: u8 = 4;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(4)   - 8bits
        // 2) Requested peers  - 8bits
        // 3) Nonce            - 64bits
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(self.requested_peers).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();

        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<RequestPeers>, NetworkErr> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if bytes.len() != 10 {
            return Err(NetworkErr::BadFormat);
        }

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

        let packet = RequestPeers {
            nonce,
            requested_peers,
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &RequestPeers,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!("Received RequestPeers packet from: {:?}", addr);

        let num_of_peers = packet.requested_peers as usize;
        let peers = network.peers();
        let peers = peers.read(); 
        let node_id = peers.get(addr).unwrap().id.as_ref().unwrap().clone(); // This is ugly
        let addresses: Vec<SocketAddr> = peers
            .iter()
            // Don't send the address of the requester
            .filter(|(peer_addr, peer)| {
                peer.id.is_some() && peer.id != Some(node_id.clone()) && *peer_addr != addr
            })
            .take(num_of_peers)
            .map(|(addr, _)| addr)
            .cloned()
            .collect();

        let mut send_peers = SendPeers::new(addresses, packet.nonce);
        network.send_to_peer(addr, send_peers.to_bytes())?;

        Ok(())
    }
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
            nonce: Arbitrary::arbitrary(g),
            requested_peers: Arbitrary::arbitrary(g),
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
    }
}
