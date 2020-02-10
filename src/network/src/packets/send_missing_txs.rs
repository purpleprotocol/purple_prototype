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
use transactions::Tx;
use rlp::*;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct SendMissingTxs {
    pub(crate) txs: Vec<Arc<Tx>>,
    pub(crate) nonce: u64,
}

impl SendMissingTxs {
    pub fn new(nonce: u64, txs: Vec<Arc<Tx>>) -> SendMissingTxs {
        SendMissingTxs { 
            txs,
            nonce,
        }
    }
}

impl Packet for SendMissingTxs {
    const PACKET_TYPE: u8 = 18;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;

        // Encode transaction set using RLP
        let mut encoder = RlpStream::new_list(self.txs.len());

        for tx in self.txs.iter() {
            let tx_bytes = tx.to_bytes();
            encoder.append(&tx_bytes);
        }

        let encoded_txs = encoder.out();
        let txs_len = encoded_txs.len();

        // Packet structure:
        // 1) Packet type(18)   - 8bits
        // 2) Txs length        - 32bits
        // 2) Nonce             - 64bits
        // 3) Transaction set   - Txs length bytes
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u32::<BigEndian>(txs_len as u32).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&encoded_txs);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<SendMissingTxs>, NetworkErr> {
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

        let txs_len = if let Ok(result) = rdr.read_u32::<BigEndian>() {
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

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..13).collect();

        let txs = if buf.len() == txs_len as usize {
            let decoder = Rlp::new(&buf);
            let mut txs = Vec::new();

            if decoder.is_list() {
                for bytes in decoder.iter() {
                    if bytes.is_data() {
                        let data = bytes.data().map_err(|_| NetworkErr::BadFormat)?;
                        let tx = Tx::from_bytes(&data).map_err(|_| NetworkErr::BadFormat)?;

                        txs.push(Arc::new(tx));
                    } else {
                        return Err(NetworkErr::BadFormat);
                    }
                }

                txs
            } else {
                return Err(NetworkErr::BadFormat);
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = SendMissingTxs { 
            txs,
            nonce, 
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &SendMissingTxs,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for SendMissingTxs {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> SendMissingTxs {
        SendMissingTxs::new(Arbitrary::arbitrary(g), Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<SendMissingTxs>) -> bool {
            packet == SendMissingTxs::from_bytes(&SendMissingTxs::to_bytes(&packet)).unwrap()
        }
    }
}
