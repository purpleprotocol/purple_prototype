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
use crate::validation::receiver::Receiver;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::{Block, PowBlock};
use crypto::NodeId;
use crypto::{ShortHash, PublicKey as Pk, SecretKey as Sk, Signature};
use rand::Rng;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct AnnounceCheckpoint {
    pub(crate) block_hash: ShortHash,
    pub(crate) nonce: u64,
}

impl AnnounceCheckpoint {
    pub fn new(block_hash: ShortHash) -> AnnounceCheckpoint {
        let mut rng = rand::thread_rng();
        
        AnnounceCheckpoint { 
            block_hash,
            nonce: rng.gen(),
        }
    }
}

impl Packet for AnnounceCheckpoint {
    const PACKET_TYPE: u8 = 11;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(17);
        let packet_type: u8 = Self::PACKET_TYPE;

        // Packet structure:
        // 1) Packet type(11)  - 8bits
        // 2) Nonce            - 64bits
        // 3) Block hash       - 8bytes
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&self.block_hash.0);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<AnnounceCheckpoint>, NetworkErr> {
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

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..9).collect();

        let block_hash = if buf.len() == 8 as usize {
            let mut hash = [0; 8];
            hash.copy_from_slice(&buf);

            ShortHash(hash)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = AnnounceCheckpoint { 
            block_hash,
            nonce, 
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &AnnounceCheckpoint,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();   
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for AnnounceCheckpoint {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> AnnounceCheckpoint {
        AnnounceCheckpoint::new(Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<AnnounceCheckpoint>) -> bool {
            packet == AnnounceCheckpoint::from_bytes(&AnnounceCheckpoint::to_bytes(&packet)).unwrap()
        }
    }
}
