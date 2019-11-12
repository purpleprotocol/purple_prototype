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
use crate::peer::ConnectionType;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use events::Event;
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardEvent {
    event: Event,
}

impl ForwardEvent {
    pub fn new(event: Event) -> ForwardEvent {
        ForwardEvent { event }
    }
}

impl Packet for ForwardEvent {
    const PACKET_TYPE: u8 = 8;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        let event = self.event.to_bytes();

        // Packet structure:
        // 1) Packet type(8)   - 8bits
        // 2) Event length     - 32bits
        // 3) Event            - Binary of event length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u32::<BigEndian>(event.len() as u32).unwrap();
        buffer.extend_from_slice(&event);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<ForwardEvent>, NetworkErr> {
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

        let event_len = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..5).collect();

        let event = if buf.len() == event_len as usize {
            match Event::from_bytes(&buf) {
                Ok(result) => result,
                _ => return Err(NetworkErr::BadFormat),
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = ForwardEvent { event };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &ForwardEvent,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for ForwardEvent {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ForwardEvent {
        ForwardEvent {
            event: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<ForwardEvent>) -> bool {
            tx == ForwardEvent::from_bytes(&ForwardEvent::to_bytes(&tx)).unwrap()
        }
    }
}
