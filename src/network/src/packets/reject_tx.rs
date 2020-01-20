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
use crate::protocol_flow::transaction_propagation::Pair;
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::validation::sender::Sender;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::{Block, PowBlock};
use crypto::NodeId;
use crypto::{ShortHash, PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TxRejectStatus {
    NoMempool,
    MempoolFull,
    Witnessed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RejectTx {
    pub(crate) nonce: u64,
    pub(crate) status: TxRejectStatus,
}

impl RejectTx {
    pub fn new(nonce: u64, status: TxRejectStatus) -> RejectTx {
        RejectTx { 
            nonce,
            status,
        }
    }
}

impl Packet for RejectTx {
    const PACKET_TYPE: u8 = 10;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;
        let status = match self.status {
            TxRejectStatus::Witnessed => 0,
            TxRejectStatus::MempoolFull => 1,
            TxRejectStatus::NoMempool => 2,
        };

        // Packet structure:
        // 1) Packet type(8)   - 8bits
        // 2) Reject status    - 8bits
        // 2) Nonce            - 64bits
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(status).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<RejectTx>, NetworkErr> {
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
                0 => TxRejectStatus::Witnessed,
                1 => TxRejectStatus::MempoolFull,
                2 => TxRejectStatus::NoMempool,
                _ => return Err(NetworkErr::BadFormat)
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

        let packet = RejectTx { 
            nonce, 
            status,
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &RejectTx,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received RejectTx packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve pairs map
        let pairs = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.transaction_propagation.pairs.clone()
        };

        let sender = {
            if let Some(pair) = pairs.get(&packet.nonce) {
                pair.sender.clone()
            } else {
                return Err(NetworkErr::AckErr);
            }
        };

        debug!("Acking RejectTx {}", packet.nonce);

        // Ack packet
        {
            let packet = InboundPacket::RejectTx(Arc::new(packet.clone()));
            let mut sender = sender.lock();
            sender.acknowledge(&packet)?;
        }

        debug!("RejectTx {} acked!", packet.nonce);

        Ok(())
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use rand::Rng;

#[cfg(test)]
impl Arbitrary for RejectTx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> RejectTx {
        RejectTx::new(Arbitrary::arbitrary(g), Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for TxRejectStatus {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> TxRejectStatus {
        let mut rng = rand::thread_rng();
        let num = rng.gen_range(0, 3);

        match num {
            0 => TxRejectStatus::Witnessed,
            1 => TxRejectStatus::MempoolFull,
            2 => TxRejectStatus::NoMempool,
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<RejectTx>) -> bool {
            packet == RejectTx::from_bytes(&RejectTx::to_bytes(&packet)).unwrap()
        }
    }
}
