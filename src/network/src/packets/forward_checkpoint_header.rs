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
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::{Block, CheckpointBlock};
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardCheckpointHeader {
    block: Arc<CheckpointBlock>,
}

impl ForwardCheckpointHeader {
    pub fn new(block: Arc<CheckpointBlock>) -> ForwardCheckpointHeader {
        ForwardCheckpointHeader { block }
    }
}

impl Packet for ForwardCheckpointHeader {
    const PACKET_TYPE: u8 = 15;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;
        let block = self.block.to_bytes();

        // Packet structure:
        // 1) Packet type(15)  - 8bits
        // 2) Block length     - 16bits
        // 3) Block            - Binary of block length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u16::<BigEndian>(block.len() as u16).unwrap();
        buffer.extend_from_slice(&block);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<ForwardCheckpointHeader>, NetworkErr> {
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

        let block_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..3).collect();

        let block = if buf.len() == block_len as usize {
            match CheckpointBlock::from_bytes(&buf) {
                Ok(result) => result,
                _ => return Err(NetworkErr::BadFormat),
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = ForwardCheckpointHeader { block };
        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &ForwardCheckpointHeader,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for ForwardCheckpointHeader {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ForwardCheckpointHeader {
        ForwardCheckpointHeader {
            block: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::CheckpointBlock;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<ForwardCheckpointHeader>) -> bool {
            tx == ForwardCheckpointHeader::from_bytes(&ForwardCheckpointHeader::to_bytes(&tx)).unwrap()
        }
    }
}
