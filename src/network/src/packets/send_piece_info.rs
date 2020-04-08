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
use crate::packets::SendPeers;
use crate::peer::ConnectionType;
use crate::priority::NetworkPriority;
use crate::validation::receiver::Receiver;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::ShortHash;
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq)]
pub struct SendPieceInfo {
    /// Randomly generated nonce
    pub(crate) nonce: u64,

    /// The hashes of all the sub-pieces
    pub(crate) hashes: Vec<ShortHash>,
}

impl SendPieceInfo {
    pub fn new(hashes: Vec<ShortHash>, nonce: u64) -> SendPieceInfo {
        if hashes.len() > 16 {
            panic!("Cannot have a sub-pieces count that is greater than 16!");
        } else if hashes.len() == 0 {
            panic!("Cannot receive an empty hashes vector!");
        }

        SendPieceInfo {
            hashes,
            nonce,
        }
    }
}

#[async_trait]
impl Packet for SendPieceInfo {
    const PACKET_TYPE: u8 = 15;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(10 + 16 * 8);
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(15)   - 8bits
        // 2) Sub-pieces count  - 8bits
        // 2) Nonce             - 64bits
        // 3) Sub-pieces hashes - Sub-pieces count * 8 bytes
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(self.hashes.len() as u8).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        
        // Write sub-pieces hashes
        for hash in self.hashes.iter() {
            buffer.extend_from_slice(&hash.0);
        }

        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<SendPieceInfo>, NetworkErr> {
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

        let sub_pieces_count = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if sub_pieces_count > 16 || sub_pieces_count == 0 {
            return Err(NetworkErr::BadFormat);
        }

        if bytes.len() != 10 + sub_pieces_count as usize * 8 {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(2);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let mut hashes = Vec::with_capacity(sub_pieces_count as usize);

        // Decode hashes
        for i in 0..sub_pieces_count as usize {
            let mut hash_bytes = [0; 8];
            let i = i * 8;
            let start_i = i + 10;
            let end_i = i + 18;

            hash_bytes.copy_from_slice(&bytes[start_i..end_i]);
            hashes.push(ShortHash(hash_bytes));
        }

        let packet = SendPieceInfo {
            nonce,
            hashes
        };

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
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for SendPieceInfo {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> SendPieceInfo {
        SendPieceInfo {
            nonce: Arbitrary::arbitrary(g),
            hashes: (0..16).into_iter().map(|_| Arbitrary::arbitrary(g)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<SendPieceInfo>) -> bool {
            tx == SendPieceInfo::from_bytes(&SendPieceInfo::to_bytes(&tx)).unwrap()
        }
    }
}
