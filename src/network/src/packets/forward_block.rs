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
use chain::{Block, BlockWrapper};
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardBlock {
    block: BlockWrapper,
}

impl ForwardBlock {
    pub fn new(block: BlockWrapper) -> ForwardBlock {
        ForwardBlock { block }
    }
}

impl Packet for ForwardBlock {
    const PACKET_TYPE: u8 = 6;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        let block = self.block.to_bytes();

        // Packet structure:
        // 1) Packet type(6)   - 8bits
        // 2) Block length     - 32bits
        // 3) Block            - Binary of block length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u32::<BigEndian>(block.len() as u32).unwrap();
        buffer.extend_from_slice(&block);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<ForwardBlock>, NetworkErr> {
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

        let block_len = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..5).collect();

        let block = if buf.len() == block_len as usize {
            match BlockWrapper::from_bytes(&buf) {
                Ok(result) => result,
                _ => return Err(NetworkErr::BadFormat),
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = ForwardBlock { block };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &ForwardBlock,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        match packet.block {
            BlockWrapper::PowBlock(ref block) => {
                info!("Received POW block with hash {} and height {}", block.block_hash().unwrap(), block.height());

                let pow_chain = network.pow_chain_ref();

                // Do not push block to queue if we already
                // have it stored in the chain.
                if pow_chain.query(&block.block_hash().unwrap()).is_some() {
                    Ok(())
                } else {
                    let mut sender = network.pow_chain_sender().clone();

                    #[cfg(not(test))]
                    sender.try_send((addr.clone(), block.clone())).unwrap();

                    #[cfg(test)]
                    sender.send((addr.clone(), block.clone())).unwrap();

                    Ok(())
                }
            }

            BlockWrapper::StateBlock(ref block) => {
                info!("Received state block with hash {} and height {}", block.block_hash().unwrap(), block.height());

                let state_chain = network.state_chain_ref();

                // Do not push block to queue if we already
                // have it stored in the chain.
                if state_chain.query(&block.block_hash().unwrap()).is_some() {
                    Ok(())
                } else {
                    let mut sender = network.state_chain_sender().clone();

                    #[cfg(not(test))]
                    sender.try_send((addr.clone(), block.clone())).unwrap();

                    #[cfg(test)]
                    sender.send((addr.clone(), block.clone())).unwrap();

                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for ForwardBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ForwardBlock {
        ForwardBlock {
            block: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<ForwardBlock>) -> bool {
            tx == ForwardBlock::from_bytes(&ForwardBlock::to_bytes(&tx)).unwrap()
        }
    }
}
