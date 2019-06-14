/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::peer::ConnectionType;
use crate::interface::NetworkInterface;
use crate::node_id::NodeId;
use crate::error::NetworkErr;
use crate::packet::Packet;
use chain::{Block, BlockWrapper};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use chrono::prelude::*;
use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Cursor;
use std::str;

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardBlock {
    node_id: NodeId,
    block: Arc<BlockWrapper>,
    timestamp: DateTime<Utc>,
    signature: Option<Signature>,
}

impl ForwardBlock {
    pub const PACKET_TYPE: u8 = 4;

    pub fn new(node_id: NodeId, block: Arc<BlockWrapper>) -> ForwardBlock {
        ForwardBlock {
            node_id,
            block,
            timestamp: Utc::now(),
            signature: None
        }
    }
}

impl Packet for ForwardBlock {
    fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    fn verify_sig(&self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.node_id.0),
            None => false,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        let mut signature = if let Some(signature) = &self.signature {
            signature.inner_bytes()
        } else {
            panic!("Signature field is missing");
        };

        let timestamp = self.timestamp().to_rfc3339();
        let timestamp_length = timestamp.len() as u8;
        let node_id = &self.node_id.0;
        let block = self.block.to_bytes();

        // Packet structure:
        // 1) Packet type(4)   - 8bits
        // 2) Timestamp length - 8bits
        // 3) Block length     - 32bits
        // 4) Node id          - 32byte binary
        // 5) Signature        - 64byte binary
        // 6) Timestamp        - Binary of timestamp length
        // 7) Block            - Binary of block length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(timestamp_length).unwrap();
        buffer.write_u32::<BigEndian>(block.len() as u32).unwrap();
        buffer.extend_from_slice(&node_id.0);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(timestamp.as_bytes());
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

        let timestamp_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };
        
        rdr.set_position(2);

        let block_len = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..6).collect();

        let node_id = if buf.len() > 32 as usize {
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&node_id_vec);

            NodeId(Pk(b))
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();
            Signature::new(&sig_vec)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let timestamp = if buf.len() > timestamp_len as usize {
            let result: Vec<u8> = buf.drain(..timestamp_len as usize).collect();
            
            match str::from_utf8(&result) {
                Ok(result) => match DateTime::parse_from_rfc3339(result) {
                    Ok(result) => Utc.from_utc_datetime(&result.naive_utc()),
                    _ => return Err(NetworkErr::BadFormat)
                },
                Err(_) => return Err(NetworkErr::BadFormat)
            } 
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let block = if buf.len() == block_len as usize {
            match BlockWrapper::from_bytes(&buf) {
                Ok(result) => result,
                _ => return Err(NetworkErr::BadFormat)
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = ForwardBlock {
            node_id,
            block,
            timestamp,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }

    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn handle<N: NetworkInterface>(network: &mut N, addr: &SocketAddr, packet: &ForwardBlock, _conn_type: ConnectionType) -> Result<(), NetworkErr> {
        match *packet.block {
            BlockWrapper::EasyBlock(ref block) => {
                let easy_chain = network.easy_chain_ref();

                // Do not push block to queue if we already  
                // have it stored in the chain.
                if easy_chain.query(&block.block_hash().unwrap()).is_some() {
                    Ok(())
                } else {
                    let sender = network.easy_chain_sender();
                    sender.send((addr.clone(), block.clone())).unwrap();

                    Ok(())
                }
            }

            BlockWrapper::HardBlock(ref block) => {
                let hard_chain = network.hard_chain_ref();

                // Do not push block to queue if we already  
                // have it stored in the chain.
                if hard_chain.query(&block.block_hash().unwrap()).is_some() {
                    Ok(())
                } else {
                    let sender = network.hard_chain_sender();
                    sender.send((addr.clone(), block.clone())).unwrap();

                    Ok(())
                }
            }
        }
    }
}

fn assemble_message(obj: &ForwardBlock) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    let block_hash = obj.block.block_hash().unwrap();
    let node_id = (obj.node_id.0).0;
    let timestamp = obj.timestamp.to_rfc3339();

    buf.extend_from_slice(&[ForwardBlock::PACKET_TYPE]);
    buf.extend_from_slice(&block_hash.0);
    buf.extend_from_slice(&node_id);
    buf.extend_from_slice(timestamp.as_bytes());

    buf
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
use chain::EasyBlock;

#[cfg(test)]
impl Arbitrary for ForwardBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ForwardBlock {
        let (pk, _) = crypto::gen_kx_keypair();
        let id = Identity::new();
        let timestamp = Utc::now();

        ForwardBlock {
            node_id: NodeId(*id.pkey()),
            block: Arbitrary::arbitrary(g),
            timestamp,
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::EasyBlock;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<ForwardBlock>) -> bool {
            tx == ForwardBlock::from_bytes(&ForwardBlock::to_bytes(&tx)).unwrap()
        }

        fn verify_signature(block: Arc<EasyBlock>) -> bool {
            let id = Identity::new();
            let timestamp = Utc::now();
            let mut packet = ForwardBlock {
                node_id: NodeId(*id.pkey()),
                block: Arc::new(BlockWrapper::EasyBlock(block)),
                signature: None,
                timestamp
            };

            packet.sign(&id.skey());
            packet.verify_sig()
        }

    }
}