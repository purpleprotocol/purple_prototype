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

use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::packet::Packet;
use crate::peer::ConnectionType;
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::protocol_flow::transaction_propagation::Pair;
use crate::validation::sender::Sender;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::NodeId;
use crypto::ShortHash;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestTx {
    pub(crate) nonce: u64,
}

impl RequestTx {
    pub fn new(nonce: u64) -> RequestTx {
        RequestTx { nonce }
    }
}

impl Packet for RequestTx {
    const PACKET_TYPE: u8 = 7;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(7);
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(8)   - 8bits
        // 2) Nonce            - 64bits
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<RequestTx>, NetworkErr> {
        let mut rdr = Cursor::new(bin);
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

        let packet = RequestTx { nonce };

        Ok(Arc::new(packet.clone()))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: Arc<RequestTx>,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received RequestTx packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve pairs map
        let pairs = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.transaction_propagation.pairs.clone()
        };

        let sender = {
            if let Some(pair) = pairs.get(&packet.nonce) {
                pair.sender.clone()
            } else {
                return Err(NetworkErr::AckErr);
            }
        };

        debug!("Acking RequestTx {}", packet.nonce);

        // Ack packet
        {
            let packet = InboundPacket::RequestTx(packet.clone());
            let mut sender = sender.lock();
            sender.acknowledge(&packet)?;
        }

        debug!("RequestTx {} acked!", packet.nonce);

        Ok(())
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for RequestTx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RequestTx {
        RequestTx::new(Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<RequestTx>) -> bool {
            packet == RequestTx::from_bytes(&RequestTx::to_bytes(&packet)).unwrap()
        }
    }
}
