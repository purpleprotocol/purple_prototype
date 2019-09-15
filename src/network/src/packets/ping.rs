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
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::net::SocketAddr;
use std::sync::Arc;
use std::io::Cursor;
use rand::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Ping {
    /// Randomly generated nonce
    pub(crate) nonce: u64,
}

impl Ping {
    pub fn new() -> Ping {
        let mut rng = rand::thread_rng();

        Ping {
            nonce: rng.gen(),
        }
    }
}

impl Packet for Ping {
    const PACKET_TYPE: u8 = 2;

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &Ping,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();

        // Ping packet structure:
        // 1) Packet type(2)   - 8bits
        // 2) Nonce            - 64bits
        buffer.write_u8(Self::PACKET_TYPE).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<Ping>, NetworkErr> {
        let mut rdr = Cursor::new(bin.to_vec());
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

        let packet = Ping {
            nonce,
        };

        Ok(Arc::new(packet))
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for Ping {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Ping {
        Ping {
            nonce: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<Ping>) -> bool {
            packet == Ping::from_bytes(&Ping::to_bytes(&packet)).unwrap()
        }
    }
}