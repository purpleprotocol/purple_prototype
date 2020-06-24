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
use crate::connection::*;
use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::packet::Packet;
use crate::packets::SendBlocks;
use crate::peer::ConnectionType;
use crate::priority::NetworkPriority;
use crate::validation::receiver::Receiver;
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use rand::prelude::*;
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestBlocks {
    /// Randomly generated nonce
    pub(crate) nonce: u64,

    /// The number of requested blocks
    pub(crate) requested_blocks: u8,
}

impl RequestBlocks {
    pub fn new(requested_blocks: u8) -> RequestBlocks {
        let mut rng = rand::thread_rng();

        RequestBlocks {
            requested_blocks,
            nonce: rng.gen(),
        }
    }
}

#[async_trait]
impl Packet for RequestBlocks {
    const PACKET_TYPE: u8 = 20;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(10);
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(20)   - 8bits
        // 2) Requested peers  - 8bits
        // 3) Nonce            - 64bits
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(self.requested_blocks).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();

        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<RequestBlocks>, NetworkErr> {
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

        let requested_blocks = if let Ok(result) = rdr.read_u8() {
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

        let packet = RequestBlocks {
            nonce,
            requested_blocks,
        };

        Ok(Arc::new(packet.clone()))
    }

    async fn handle<N: NetworkInterface, S: AsyncWrite + AsyncWriteExt + Unpin + Send + Sync>(
        network: &mut N,
        sock: &mut S,
        addr: &SocketAddr,
        packet: Arc<Self>,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received RequestBlocks packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve receiver mutex
        let receiver = {
            let peers = network.peers();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.request_blocks.receiver.clone()
        };

        // Attempt to receive packet
        let packet = {
            let mut receiver = receiver.lock();
            receiver.receive(network as &N, addr, &packet)?
        };

        debug!("Sending SendBlocks packet to {}", addr);

        // Send `SendBlocks` packet back to peer
        network.send_to_peer(addr, &packet, NetworkPriority::Medium)?;

        debug!("SendBlocks packet sent to {}", addr);

        Ok(())
    }

    fn to_client_request(&self) -> Option<ClientRequest> {
        Some(ClientRequest::RequestBlocks)
    }

    async fn start_client_protocol_flow<
        N: NetworkInterface,
        S: AsyncWrite + AsyncWriteExt + AsyncRead + AsyncReadExt + Unpin + Send + Sync,
    >(
        network: &mut N,
        sock: &mut S,
        peer: &SocketAddr,
    ) -> Result<(), NetworkErr> {
        // Read initial packet from stream
        let bytes = read_raw_packet(sock, network as &_, peer, true)
            .await
            .map_err(|_| NetworkErr::IoErr)?;

        // Deserialize packet
        let packet = SendBlocks::from_bytes(&bytes)?;

        // Handle packet
        SendBlocks::handle(network, sock, peer, packet, ConnectionType::Client).await?;

        Ok(())
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for RequestBlocks {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RequestBlocks {
        let id = Identity::new();

        RequestBlocks {
            nonce: Arbitrary::arbitrary(g),
            requested_blocks: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<RequestBlocks>) -> bool {
            tx == RequestBlocks::from_bytes(&RequestBlocks::to_bytes(&tx)).unwrap()
        }
    }
}
