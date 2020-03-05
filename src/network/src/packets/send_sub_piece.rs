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
use crate::packets::SendPeers;
use crate::peer::ConnectionType;
use crate::priority::NetworkPriority;
use crate::validation::receiver::Receiver;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::ShortHash;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

/// Maximum size of a sub-piece. 16kb
pub const SUB_PIECE_MAX_SIZE: usize = 16_384;

#[derive(Debug, Clone, PartialEq)]
pub struct SendSubPiece {
    /// Randomly generated nonce
    pub(crate) nonce: u64,

    /// The sub-piece raw data
    pub(crate) sub_piece: Vec<u8>,
}

impl SendSubPiece {
    pub fn new(sub_piece: Vec<u8>, nonce: u64) -> SendSubPiece {
        if sub_piece.len() > SUB_PIECE_MAX_SIZE {
            panic!("Cannot have a sub-piece bigger than 16kb!");
        } else if sub_piece.len() == 0 {
            panic!("Cannot have an empty sub-piece!");
        }

        SendSubPiece {
            sub_piece,
            nonce,
        }
    }
}

impl Packet for SendSubPiece {
    const PACKET_TYPE: u8 = 17;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(11 + self.sub_piece.len());
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(17)   - 8bits
        // 2) Sub-piece length  - 16bits (max 16kb)
        // 3) Nonce             - 64bits
        // 4) Sub-piece         - Sub-piece length bytes
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u16::<BigEndian>(self.sub_piece.len() as u16).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&self.sub_piece);
        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<SendSubPiece>, NetworkErr> {
        let mut rdr = Cursor::new(bytes);
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if packet_type != Self::PACKET_TYPE {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(1);

        let sub_piece_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result as usize
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if sub_piece_len > SUB_PIECE_MAX_SIZE || sub_piece_len == 0 {
            return Err(NetworkErr::BadFormat);
        }

        if bytes.len() != 11 + sub_piece_len {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(3);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let mut sub_piece = Vec::with_capacity(sub_piece_len);
        sub_piece.extend_from_slice(&bytes[11..]);

        let packet = SendSubPiece {
            nonce,
            sub_piece,
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &SendSubPiece,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for SendSubPiece {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> SendSubPiece {
        SendSubPiece {
            nonce: Arbitrary::arbitrary(g),
            sub_piece: (0..500).into_iter().map(|_| Arbitrary::arbitrary(g)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<SendSubPiece>) -> bool {
            tx == SendSubPiece::from_bytes(&SendSubPiece::to_bytes(&tx)).unwrap()
        }
    }
}
