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
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::NodeId;
use crypto::ShortHash;
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestBlock {
    pub(crate) nonce: u64,

    /// Number of transactions in the receiver's mempool
    pub(crate) tx_count: u32,
}

impl RequestBlock {
    pub fn new(nonce: u64, tx_count: u32) -> RequestBlock {
        RequestBlock { nonce, tx_count }
    }
}

#[async_trait]
impl Packet for RequestBlock {
    const PACKET_TYPE: u8 = 11;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(11);
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(11)   - 8bits
        // 2) Tx count          - 32bits
        // 2) Nonce             - 64bits
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u32::<BigEndian>(self.tx_count).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<RequestBlock>, NetworkErr> {
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

        let tx_count = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        rdr.set_position(5);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = RequestBlock { nonce, tx_count };

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
        Some(ClientRequest::RequestBlock)
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for RequestBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RequestBlock {
        RequestBlock::new(Arbitrary::arbitrary(g), Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<RequestBlock>) -> bool {
            packet == RequestBlock::from_bytes(&RequestBlock::to_bytes(&packet)).unwrap()
        }
    }
}