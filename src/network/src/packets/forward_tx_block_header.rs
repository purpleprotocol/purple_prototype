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
use crate::peer::ConnectionType;
use bloom::Bloom;
use purple_iblt::PurpleIBLT;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::{Block, TransactionBlock};
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

pub const IBLT_C_CONST: f32 = 5.54517744448;
pub const IBLT_R_CONST: f32 = 16.5;

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardTxBlockHeader {
    block: Arc<TransactionBlock>,
    bloom_filter: Option<Bloom>,
    iblt: Option<PurpleIBLT>,
    nonce: u64,
}

impl ForwardTxBlockHeader {
    pub fn new(block: Arc<TransactionBlock>, nonce: u64, mempool_size: u32) -> Result<ForwardTxBlockHeader, &'static str> {    
        if let Some(txs) = &block.transactions {
            let txs = txs.read();

            if !txs.is_empty() {
                let M: u32 = mempool_size;
                let N: u32 = txs.len() as u32;
                let A: u32 = ((N as f32) / (IBLT_C_CONST * IBLT_R_CONST)).trunc() as u32;
                
                // Calculate bloom filter table size based on the receiver's mempool size
                let bloom_table_size = ((A as f32) / (M - N) as f32).trunc() as u32;

                // Fallback to txs count if the calculation results in 0
                let bloom_table_size = if bloom_table_size == 0 {
                    txs.len() as u32
                } else {
                    bloom_table_size
                };

                // Create bloom filter
                let mut bloom_filter = Bloom::new(bloom_table_size, txs.len() as u32);

                // Add transaction hashes to the bloom filter
                for tx in txs.iter() {
                    let tx_hash = tx.tx_hash().unwrap().to_short();
                    bloom_filter.set(&tx_hash.0);
                }

                // Calculate IBLT size
                let iblt_size = (IBLT_R_CONST * (A as f32)).trunc() as u32;

                // Fallback to txs count if the calculation results in 0
                let iblt_size = if iblt_size == 0 {
                    txs.len() as u32
                } else {
                    iblt_size 
                };

                // Dynamically find a suitable hash functions value 
                let hash_funcs = {
                    let mut result: u8 = if iblt_size >= 4 {
                        4
                    } else {
                        1
                    };

                    while iblt_size % (result as u32) != 0 {
                        result += 1;
                    } 

                    result
                };

                // Create IBLT
                let mut iblt = PurpleIBLT::new(
                    iblt_size as usize, 
                    0, 
                    hash_funcs,
                ).map_err(|_| "Could not create IBLT")?;

                // Insert transaction hashes in IBLT
                for tx in txs.iter() {
                    let tx_hash = tx.tx_hash().unwrap().to_short();
                    let hash_le = decode_le_u64!(&tx_hash.0).unwrap();
                    iblt.insert(hash_le, &[]).unwrap();
                }

                Ok(ForwardTxBlockHeader { 
                    block: block.clone(),
                    bloom_filter: Some(bloom_filter),
                    iblt: Some(iblt),
                    nonce,
                })
            } else {
                Ok(ForwardTxBlockHeader { 
                    block: block.clone(),
                    bloom_filter: None,
                    iblt: None,
                    nonce,
                })
            }
        } else {
            Err("There are no attached transactions to the block header!")
        }        
    }
}

impl Packet for ForwardTxBlockHeader {
    const PACKET_TYPE: u8 = 16;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;
        let block = self.block.to_bytes();

        // Packet structure:
        // 1) Packet type(16)     - 8bits
        // 2) Is empty            - 1byte
        // 2) Block length        - 16bits
        // 3) Bloom filter length - 16bits (Optional)
        // 4) IBLT length         - 16bits (Optional)
        // 5) Nonce               - 64bits 
        // 6) Bloom filter        - Binary of bloom filter length (Optional)
        // 7) IBLT                - Binary of IBLT length (Optional)
        // 8) Block               - Binary of block length
        if let (Some(bloom), Some(iblt)) = (&self.bloom_filter, &self.iblt) {
            let bloom = bloom.to_bytes();
            let iblt = iblt.to_bytes();

            buffer.write_u8(packet_type).unwrap();
            buffer.write_u8(1).unwrap();
            buffer.write_u16::<BigEndian>(block.len() as u16).unwrap();
            buffer.write_u16::<BigEndian>(bloom.len() as u16).unwrap();
            buffer.write_u16::<BigEndian>(iblt.len() as u16).unwrap();
            buffer.write_u64::<BigEndian>(self.nonce).unwrap();
            buffer.extend_from_slice(&bloom);
            buffer.extend_from_slice(&iblt);
            buffer.extend_from_slice(&block);
            buffer
        } else {
            buffer.write_u8(packet_type).unwrap();
            buffer.write_u8(0).unwrap();
            buffer.write_u16::<BigEndian>(block.len() as u16).unwrap();
            buffer.write_u64::<BigEndian>(self.nonce).unwrap();
            buffer.extend_from_slice(&block);
            buffer
        }
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<ForwardTxBlockHeader>, NetworkErr> {
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

        let is_empty = if let Ok(result) = rdr.read_u8() {
            match result {
                0 => true,
                1 => false,
                _ => return Err(NetworkErr::BadFormat),
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        rdr.set_position(2);

        if !is_empty {
            let block_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
                result
            } else {
                return Err(NetworkErr::BadFormat);
            };

            rdr.set_position(4);

            let bloom_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
                result
            } else {
                return Err(NetworkErr::BadFormat);
            };

            rdr.set_position(6);

            let iblt_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
                result
            } else {
                return Err(NetworkErr::BadFormat);
            };

            rdr.set_position(8);

            let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
                result
            } else {
                return Err(NetworkErr::BadFormat);
            };

            // Consume cursor
            let mut buf: Vec<u8> = rdr.into_inner();
            let _: Vec<u8> = buf.drain(..16).collect();

            let bloom_filter = if buf.len() > bloom_len as usize {
                let buf: Vec<u8> = buf.drain(..(bloom_len as usize)).collect();

                match Bloom::from_bytes(&buf) {
                    Ok(result) => result,
                    _ => return Err(NetworkErr::BadFormat),
                }
            } else {
                return Err(NetworkErr::BadFormat);
            };

            let iblt = if buf.len() > iblt_len as usize {
                let buf: Vec<u8> = buf.drain(..(iblt_len as usize)).collect();

                match PurpleIBLT::from_bytes(&buf) {
                    Ok(result) => result,
                    _ => return Err(NetworkErr::BadFormat),
                }
            } else {
                return Err(NetworkErr::BadFormat);
            };


            let block = if buf.len() == block_len as usize {
                match TransactionBlock::from_bytes(&buf) {
                    Ok(result) => result,
                    _ => return Err(NetworkErr::BadFormat),
                }
            } else {
                return Err(NetworkErr::BadFormat);
            };

            let packet = ForwardTxBlockHeader { 
                block,
                bloom_filter: Some(bloom_filter),
                iblt: Some(iblt),
                nonce,
            };

            Ok(Arc::new(packet))
        } else {
            let block_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
                result
            } else {
                return Err(NetworkErr::BadFormat);
            };

            rdr.set_position(4);

            let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
                result
            } else {
                return Err(NetworkErr::BadFormat);
            };

            // Consume cursor
            let mut buf: Vec<u8> = rdr.into_inner();
            let _: Vec<u8> = buf.drain(..12).collect();

            let block = if buf.len() == block_len as usize {
                match TransactionBlock::from_bytes(&buf) {
                    Ok(result) => result,
                    _ => return Err(NetworkErr::BadFormat),
                }
            } else {
                return Err(NetworkErr::BadFormat);
            };

            let packet = ForwardTxBlockHeader { 
                block,
                bloom_filter: None,
                iblt: None,
                nonce,
            };

            Ok(Arc::new(packet))
        }
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &ForwardTxBlockHeader,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use rand::Rng;

#[cfg(test)]
impl Arbitrary for ForwardTxBlockHeader {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ForwardTxBlockHeader {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(0, 2);

        let (bloom_filter, iblt) = if random == 0 {
            (Some(Arbitrary::arbitrary(g)), Some(Arbitrary::arbitrary(g)))
        } else {
            (None, None)
        };

        ForwardTxBlockHeader {
            block: Arbitrary::arbitrary(g),
            bloom_filter,
            iblt,
            nonce: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::TransactionBlock;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<ForwardTxBlockHeader>) -> bool {
            tx == ForwardTxBlockHeader::from_bytes(&ForwardTxBlockHeader::to_bytes(&tx)).unwrap()
        }
    }
}
