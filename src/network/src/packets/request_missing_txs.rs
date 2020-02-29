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

#![allow(non_snake_case)]

use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::packet::Packet;
use crate::packets::forward_tx_block_header::{IBLT_C_CONST, IBLT_R_CONST};
use crate::peer::ConnectionType;
use crate::validation::sender::Sender;
use bloom::Bloom;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::NodeId;
use crypto::ShortHash;
use rand::Rng;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestMissingTxs {
    pub(crate) nonce: u64,
    pub(crate) block_hash: ShortHash,
    pub(crate) tx_filter: Bloom,
}

impl RequestMissingTxs {
    pub fn new(block_hash: ShortHash, tx_ids: &[ShortHash]) -> RequestMissingTxs {
        let mut rng = rand::thread_rng();

        // One byte per tx id, keep it simple for now
        let mut tx_filter = Bloom::new(tx_ids.len() as u32, tx_ids.len() as u32);

        // Add missing tx ids to the bloom filter
        for tx_hash in tx_ids {
            tx_filter.set(&tx_hash.0);
        }

        RequestMissingTxs {
            nonce: rng.gen(),
            tx_filter,
            block_hash,
        }
    }
}

impl Packet for RequestMissingTxs {
    const PACKET_TYPE: u8 = 17;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(11);
        let packet_type: u8 = Self::PACKET_TYPE;
        let tx_filter = self.tx_filter.to_bytes();

        // Packet structure:
        // 1) Packet type(17)   - 8bits
        // 2) Bloom filter len  - 16bits
        // 3) Nonce             - 64bits
        // 4) Block hash        - 8bytes
        // 4) Tx filter         - Binary of bloom filter length
        buffer.write_u8(packet_type).unwrap();
        buffer
            .write_u16::<BigEndian>(tx_filter.len() as u16)
            .unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&self.block_hash.0);
        buffer.extend_from_slice(&tx_filter);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<RequestMissingTxs>, NetworkErr> {
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

        let tx_filter_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
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

        let block_hash = if buf.len() > 8 as usize {
            let buf: Vec<u8> = buf.drain(..8).collect();

            let mut hash = [0; 8];
            hash.copy_from_slice(&buf);

            ShortHash(hash)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let tx_filter = if buf.len() == tx_filter_len as usize {
            match Bloom::from_bytes(&buf) {
                Ok(result) => result,
                _ => return Err(NetworkErr::BadFormat),
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = RequestMissingTxs {
            nonce,
            tx_filter,
            block_hash,
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &RequestMissingTxs,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for RequestMissingTxs {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RequestMissingTxs {
        let tx_ids: Vec<ShortHash> = (0..50)
            .into_iter()
            .map(|_| Arbitrary::arbitrary(g))
            .collect();

        RequestMissingTxs::new(Arbitrary::arbitrary(g), &tx_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<RequestMissingTxs>) -> bool {
            packet == RequestMissingTxs::from_bytes(&RequestMissingTxs::to_bytes(&packet)).unwrap()
        }
    }
}
