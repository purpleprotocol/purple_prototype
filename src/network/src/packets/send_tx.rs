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
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::protocol_flow::transaction_propagation::outbound::OutboundPacket;
use crate::protocol_flow::transaction_propagation::Pair;
use crate::validation::receiver::Receiver;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chain::{Block, PowBlock};
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, ShortHash, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use triomphe::Arc;
use transactions::Tx;
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq)]
pub struct SendTx {
    pub(crate) tx: Arc<Tx>,
    pub(crate) nonce: u64,
}

impl SendTx {
    pub fn new(nonce: u64, tx: Arc<Tx>) -> SendTx {
        SendTx { tx, nonce }
    }
}

#[async_trait]
impl Packet for SendTx {
    const PACKET_TYPE: u8 = 8;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;
        let tx_bytes = self.tx.to_bytes();
        let tx_len = tx_bytes.len();

        // Packet structure:
        // 1) Packet type(9)   - 8bits
        // 2) Tx length        - 16bits
        // 2) Nonce            - 64bits
        // 3) Transaction      - Tx length bytes
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u16::<BigEndian>(tx_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&tx_bytes);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<SendTx>, NetworkErr> {
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

        let tx_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
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

        if bin.len() - 11 != tx_len as usize {
            return Err(NetworkErr::BadFormat);
        }

        let tx = Tx::from_bytes(&bin[11..]).map_err(|_| NetworkErr::BadFormat)?;
        let tx = Arc::new(tx);
        let packet = SendTx { tx, nonce };

        Ok(Arc::new(packet.clone()))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: Arc<SendTx>,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received SendTx packet from {} with nonce {}",
            addr, packet.nonce
        );

        let nonce = packet.nonce;

        // Retrieve pairs map
        let pairs = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.transaction_propagation.pairs.clone()
        };

        let receiver = {
            if let Some(pair) = pairs.get(&packet.nonce) {
                pair.receiver.clone()
            } else {
                return Err(NetworkErr::AckErr);
            }
        };

        // Attempt to receive packet
        let packet = {
            let mut receiver = receiver.lock();
            let packet = OutboundPacket::SendTx(packet);
            receiver.receive(network as &N, addr, &packet)?
        };

        // Delete pair
        pairs.remove(&nonce);

        match packet {
            InboundPacket::RejectTx(_) | InboundPacket::RequestTx(_) => unreachable!(),
            InboundPacket::None => Ok(()),
        }
    }

    fn to_client_request(&self) -> Option<ClientRequest> {
        None
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for SendTx {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> SendTx {
        SendTx::new(Arbitrary::arbitrary(g), Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::PowBlock;

    quickcheck! {
        fn serialize_deserialize(packet: Arc<SendTx>) -> bool {
            packet == SendTx::from_bytes(&SendTx::to_bytes(&packet)).unwrap()
        }
    }
}
