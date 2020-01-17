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
use chain::{Block, PowBlock};
use crypto::NodeId;
use crypto::{ShortHash, PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct AnnounceTx {
    tx_hash: ShortHash,
}

impl AnnounceTx {
    pub fn new(tx_hash: ShortHash) -> AnnounceTx {
        AnnounceTx { tx_hash }
    }
}

impl Packet for AnnounceTx {
    const PACKET_TYPE: u8 = 7;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(7)   - 8bits
        // 2) Transaction hash - 8bytes
        buffer.write_u8(packet_type).unwrap();
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

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..1).collect();

        let tx_hash = if buf.len() == 8 as usize {
            let mut hash = [0; 8];
            hash.copy_from_slice(&buf);

            ShortHash(hash)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = AnnounceTx { tx_hash };
        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &AnnounceTx,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for AnnounceTx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> AnnounceTx {
        AnnounceTx {
            tx_hash: Arbitrary::arbitrary(g),
        }
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
