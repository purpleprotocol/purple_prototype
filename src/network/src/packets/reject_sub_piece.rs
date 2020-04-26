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
use crate::validation::sender::Sender;
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::{Block, PowBlock};
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, ShortHash, Signature};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RejectSubPieceStatus {
    /// The piece is yet unknown to the peer
    Unknown,

    /// We have been chocked by this peer
    Chocked,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RejectSubPiece {
    pub(crate) nonce: u64,
    pub(crate) status: RejectSubPieceStatus,
}

impl RejectSubPiece {
    pub fn new(nonce: u64, status: RejectSubPieceStatus) -> RejectSubPiece {
        RejectSubPiece { nonce, status }
    }
}

#[async_trait]
impl Packet for RejectSubPiece {
    const PACKET_TYPE: u8 = 19;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(10);
        let packet_type: u8 = Self::PACKET_TYPE;
        let status = match self.status {
            RejectSubPieceStatus::Unknown => 0,
            RejectSubPieceStatus::Chocked => 1,
        };

        // Packet structure:
        // 1) Packet type(19)  - 8bits
        // 2) Reject status    - 8bits
        // 2) Nonce            - 64bits
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(status).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<RejectSubPiece>, NetworkErr> {
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

        let status = if let Ok(result) = rdr.read_u8() {
            match result {
                0 => RejectSubPieceStatus::Unknown,
                1 => RejectSubPieceStatus::Chocked,
                _ => return Err(NetworkErr::BadFormat),
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        rdr.set_position(2);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = RejectSubPiece { nonce, status };

        Ok(Arc::new(packet.clone()))
    }

    async fn handle<N: NetworkInterface, S: AsyncWrite + AsyncWriteExt + Unpin + Send + Sync>(
        network: &mut N,
        sock: &mut S,
        addr: &SocketAddr,
        packet: Arc<Self>,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn to_client_request(&self) -> Option<ClientRequest> {
        None
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use rand::Rng;

#[cfg(test)]
impl Arbitrary for RejectSubPiece {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RejectSubPiece {
        RejectSubPiece::new(Arbitrary::arbitrary(g), Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for RejectSubPieceStatus {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RejectSubPieceStatus {
        let mut rng = rand::thread_rng();
        let num = rng.gen_range(0, 2);

        match num {
            0 => RejectSubPieceStatus::Unknown,
            1 => RejectSubPieceStatus::Chocked,
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<RejectSubPiece>) -> bool {
            packet == RejectSubPiece::from_bytes(&RejectSubPiece::to_bytes(&packet)).unwrap()
        }
    }
}
