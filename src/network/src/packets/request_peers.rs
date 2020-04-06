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

use crate::client_request::ClientRequest;
use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::packet::Packet;
use crate::packets::SendPeers;
use crate::peer::ConnectionType;
use crate::priority::NetworkPriority;
use crate::validation::receiver::Receiver;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::prelude::*;
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestPeers {
    /// Randomly generated nonce
    pub(crate) nonce: u64,

    /// The number of requested peers
    pub(crate) requested_peers: u8,
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

#[async_trait]
impl Packet for RequestPeers {
    const PACKET_TYPE: u8 = 4;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(10);
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
        let mut rdr = Cursor::new(bytes);
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

        Ok(Arc::new(packet.clone()))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: Arc<RequestPeers>,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received RequestPeers packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve receiver mutex
        let receiver = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.request_peers.receiver.clone()
        };

        // Attempt to receive packet
        let packet = {
            let mut receiver = receiver.lock();
            receiver.receive(network as &N, addr, &packet)?
        };

        debug!("Sending SendPeers packet to {}", addr);

        // Send `SendPeers` packet back to peer
        network.send_to_peer(addr, &packet, NetworkPriority::Medium)?;

        debug!("SendPeers packet sent to {}", addr);

        Ok(())
    }

    fn to_client_request(&self) -> Option<ClientRequest> {
        Some(ClientRequest::RequestPeers)
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
