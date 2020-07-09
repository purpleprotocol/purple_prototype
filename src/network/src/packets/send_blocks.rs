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
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::*;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use rlp::{Rlp, RlpStream};
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct SendBlocks {
    /// Randomly generated nonce
    pub(crate) nonce: u64,

    /// The list of blocks to be sent
    pub(crate) blocks: Vec<Arc<PowBlock>>,
}

impl SendBlocks {
    pub fn new(blocks: Vec<Arc<PowBlock>>, nonce: u64) -> SendBlocks {
        SendBlocks { blocks, nonce }
    }

    fn encode_blocks(&self) -> Vec<u8> {
        let mut encoder = RlpStream::new_list(self.blocks.len());

        // Encode blocks with RLP
        for block in self.blocks.iter() {
            encoder.append(&block.to_bytes());
        }

        encoder.out()
    }
}

#[async_trait]
impl Packet for SendBlocks {
    const PACKET_TYPE: u8 = 21;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;
        let blocks = self.encode_blocks();
        let blocks_len = blocks.len();

        // Packet structure:
        // 1) Packet type(21)  - 8bits
        // 2) Blocks length    - 16bits
        // 3) Nonce            - 64bits
        // 4) Blocks           - Binary of blocks length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u16::<BigEndian>(blocks_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&blocks);

        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<SendBlocks>, NetworkErr> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if packet_type != Self::PACKET_TYPE {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(1);

        let blocks_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        rdr.set_position(3);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..11).collect();

        let blocks = if buf.len() == blocks_len as usize {
            let rlp = Rlp::new(&buf);
            let mut blocks: Vec<Arc<PowBlock>> = Vec::new();

            if rlp.is_list() {
                for bytes in rlp.iter() {
                    if bytes.is_data() {
                        let data = bytes.data().map_err(|_| NetworkErr::BadFormat)?;
                        let block = match PowBlock::from_bytes(data) {
                            Ok(res) => res,
                            Err(_) => return Err(NetworkErr::BadFormat),
                        };

                        blocks.push(block);
                    } else {
                        return Err(NetworkErr::BadFormat);
                    }
                }

                blocks
            } else {
                return Err(NetworkErr::BadFormat);
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = SendBlocks { nonce, blocks };

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
impl Arbitrary for SendBlocks {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> SendBlocks {
        SendBlocks {
            nonce: Arbitrary::arbitrary(g),
            blocks: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(all(test))]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<SendBlocks>) -> bool {
            tx == SendBlocks::from_bytes(&SendBlocks::to_bytes(&tx)).unwrap()
        }
    }
}
