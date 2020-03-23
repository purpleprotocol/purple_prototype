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
use rand::prelude::*;
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestSubPiece {
    /// Randomly generated nonce
    pub(crate) nonce: u64,

    /// The hash of the block
    pub(crate) block_hash: ShortHash,

    /// The hash of the piece we are requesting info for
    pub(crate) piece_hash: ShortHash,

    /// The hash of the sub-piece we are requesting
    pub(crate) sub_piece_hash: ShortHash,
}

impl RequestSubPiece {
    pub fn new(block_hash: ShortHash, piece_hash: ShortHash, sub_piece_hash: ShortHash) -> RequestSubPiece {
        let mut rng = rand::thread_rng();

        RequestSubPiece {
            block_hash,
            piece_hash,
            sub_piece_hash,
            nonce: rng.gen(),
        }
    }
}

impl Packet for RequestSubPiece {
    const PACKET_TYPE: u8 = 16;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(33);
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(16)  - 8bits
        // 2) Nonce            - 64bits
        // 3) Block hash       - 8bytes
        // 4) Piece hash       - 8bytes
        // 5) Sub-piece hash   - 8bytes
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&self.block_hash.0);
        buffer.extend_from_slice(&self.piece_hash.0);
        buffer.extend_from_slice(&self.sub_piece_hash.0);
        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<RequestSubPiece>, NetworkErr> {
        let mut rdr = Cursor::new(bytes);
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if bytes.len() != 33 {
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

        let mut block_hash_bytes = [0; 8];
        let mut piece_hash_bytes = [0; 8];
        let mut sub_piece_hash_bytes = [0; 8];
        
        block_hash_bytes.copy_from_slice(&bytes[9..17]);
        piece_hash_bytes.copy_from_slice(&bytes[17..25]);
        sub_piece_hash_bytes.copy_from_slice(&bytes[25..]);

        let block_hash = ShortHash(block_hash_bytes);
        let piece_hash = ShortHash(piece_hash_bytes);
        let sub_piece_hash = ShortHash(sub_piece_hash_bytes);

        let packet = RequestSubPiece {
            nonce,
            block_hash,
            piece_hash,
            sub_piece_hash,
        };

        Ok(Arc::new(packet.clone()))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: Arc<RequestSubPiece>,
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
impl Arbitrary for RequestSubPiece {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RequestSubPiece {
        let id = Identity::new();

        RequestSubPiece {
            nonce: Arbitrary::arbitrary(g),
            block_hash: Arbitrary::arbitrary(g),
            piece_hash: Arbitrary::arbitrary(g),
            sub_piece_hash: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<RequestSubPiece>) -> bool {
            tx == RequestSubPiece::from_bytes(&RequestSubPiece::to_bytes(&tx)).unwrap()
        }
    }
}
