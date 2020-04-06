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
use crate::peer::ConnectionType;
use crate::priority::NetworkPriority;
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::protocol_flow::transaction_propagation::outbound::OutboundPacket;
use crate::protocol_flow::transaction_propagation::Pair;
use crate::validation::receiver::Receiver;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::{Block, PowBlock};
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, ShortHash, Signature};
use rand::Rng;
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq)]
pub struct AnnounceTx {
    pub(crate) tx_hash: ShortHash,
    pub(crate) nonce: u64,
}

impl AnnounceTx {
    pub fn new(tx_hash: ShortHash) -> AnnounceTx {
        let mut rng = rand::thread_rng();

        AnnounceTx {
            tx_hash,
            nonce: rng.gen(),
        }
    }
}

#[async_trait]
impl Packet for AnnounceTx {
    const PACKET_TYPE: u8 = 6;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(17);
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(6)   - 8bits
        // 2) Nonce            - 64bits
        // 3) Transaction hash - 8bytes
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&self.tx_hash.0);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<AnnounceTx>, NetworkErr> {
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

        let tx_hash = if buf.len() == 8 as usize {
            let mut hash = [0; 8];
            hash.copy_from_slice(&buf);

            ShortHash(hash)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = AnnounceTx { tx_hash, nonce };

        Ok(Arc::new(packet.clone()))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: Arc<AnnounceTx>,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received AnnounceTx packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve pairs map
        let pairs = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.transaction_propagation.pairs.clone()
        };

        let receiver = {
            if let Some(pair) = pairs.get(&packet.nonce) {
                pair.receiver.clone()
            } else {
                let pair = Pair::default();
                pairs.insert(packet.nonce, pair.clone());
                pair.receiver.clone()
            }
        };

        // Attempt to receive packet
        let packet = {
            let mut receiver = receiver.lock();
            let packet = OutboundPacket::AnnounceTx(packet.clone());
            receiver.receive(network as &N, addr, &packet)?
        };

        match packet {
            InboundPacket::RejectTx(packet) => {
                debug!("Sending RejectTx packet to {}", addr);

                // Send `RejectTx` packet back to peer
                network.send_to_peer(addr, &packet, NetworkPriority::Medium)?;

                debug!("RejectTx packet sent to {}", addr);

                Ok(())
            }

            InboundPacket::RequestTx(packet) => {
                debug!("Sending RequestTx packet to {}", addr);

                // Send `RequestTx` packet back to peer
                network.send_to_peer(addr, &packet, NetworkPriority::Medium)?;

                debug!("RequestTx packet sent to {}", addr);

                Ok(())
            }

            InboundPacket::None => unreachable!(),
        }
    }

    fn to_client_request(&self) -> Option<ClientRequest> {
        Some(ClientRequest::AnnounceTx)
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for AnnounceTx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> AnnounceTx {
        AnnounceTx::new(Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<AnnounceTx>) -> bool {
            packet == AnnounceTx::from_bytes(&AnnounceTx::to_bytes(&packet)).unwrap()
        }
    }
}
