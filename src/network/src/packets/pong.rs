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
use crate::validation::sender::Sender;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct Pong {
    pub(crate) nonce: u64,
}

impl Pong {
    pub fn new(nonce: u64) -> Pong {
        Pong { nonce }
    }
}

impl Packet for Pong {
    const PACKET_TYPE: u8 = 3;

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: Arc<Pong>,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received Pong packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve sender mutex
        let sender = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.ping_pong.sender.clone()
        };

        debug!("Acking pong {}", packet.nonce);

        // Ack packet
        let mut sender = sender.lock();
        sender.acknowledge(&packet)?;

        debug!("Pong {} acked!", packet.nonce);

        Ok(())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(7);

        // Pong packet structure:
        // 1) Packet type(3)   - 8bits
        // 2) Nonce            - 64bits
        buffer.write_u8(Self::PACKET_TYPE).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<Pong>, NetworkErr> {
        let mut rdr = Cursor::new(bin);
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if bin.len() != 9 {
            return Err(NetworkErr::BadFormat);
        }

        if packet_type != Self::PACKET_TYPE {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(1);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = Pong { nonce };

        Ok(Arc::new(packet.clone()))
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for Pong {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Pong {
        Pong {
            nonce: Arbitrary::arbitrary(g),
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
