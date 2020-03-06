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
use crate::priority::NetworkPriority;
use crate::validation::receiver::Receiver;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::prelude::*;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct Ping {
    /// Randomly generated nonce
    pub(crate) nonce: u64,
}

impl Ping {
    pub fn new() -> Ping {
        let mut rng = rand::thread_rng();
        Ping { nonce: rng.gen() }
    }
}

impl Packet for Ping {
    const PACKET_TYPE: u8 = 2;

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: Arc<Ping>,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received Ping packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve receiver mutex
        let receiver = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            #[cfg(test)]
            {
                // We don't send a pong back if this is disabled
                if !peer.send_ping {
                    return Ok(());
                }
            }

            peer.validator.ping_pong.receiver.clone()
        };

        // Attempt to receive packet
        let pong = {
            let mut receiver = receiver.lock();
            receiver.receive(network as &N, addr, &packet)?
        };

        debug!("Sending Pong packet to {}", addr);

        // Send `Pong` packet back to peer
        network.send_to_peer(addr, pong.to_bytes(), NetworkPriority::Low)?;

        debug!("Pong packet sent to {}", addr);

        Ok(())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(7);

        // Ping packet structure:
        // 1) Packet type(2)   - 8bits
        // 2) Nonce            - 64bits
        buffer.write_u8(Self::PACKET_TYPE).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<Ping>, NetworkErr> {
        let mut rdr = Cursor::new(bin);
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        if bin.len() != 9 {
            return Err(NetworkErr::BadFormat);
        }

        if packet_type != Self::PACKET_TYPE {
            return Err(NetworkErr::BadFormat);
        }

        rdr.set_position(1);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = Ping { nonce };

        Ok(Arc::new(packet.clone()))
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for Ping {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Ping {
        Ping {
            nonce: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn peers_time_out() {
        let networks = crate::init_test_networks(2);
        let addr2 = networks[1].1;
        let network1 = networks[0].0.clone();
        let network1_c = network1.clone();
        let network2 = networks[1].0.clone();
        let network2_c = network2.clone();

        {
            // Attempt to connect the first peer to the second
            network1_c.lock().connect_no_ping(&addr2).unwrap();
        }

        // Peers should timeout in 1 second in test mode
        thread::sleep(Duration::from_millis(2000));

        {
            let network = network2_c.lock();
            let peers = network.peers();
            let peers = peers.read();
            assert!(peers.is_empty());
        };

        {
            let network = network1_c.lock();
            let peers = network.peers();
            let peers = peers.read();
            assert!(peers.is_empty());
        };
    }

    #[test]
    fn ping_pong_integration() {
        let networks = crate::init_test_networks(2);
        let addr1 = networks[0].1;
        let addr2 = networks[1].1;
        let n1 = networks[0].2.clone();
        let n2 = networks[1].2.clone();
        let network1 = networks[0].0.clone();
        let network1_c = network1.clone();
        let network2 = networks[1].0.clone();
        let network2_c = network2.clone();

        {
            // Attempt to connect the first peer to the second
            network1_c.lock().connect(&addr2).unwrap();
        }

        // Peers should timeout in 1 second in test mode
        thread::sleep(Duration::from_millis(7000));

        {
            let network = network2_c.lock();
            let peers = network.peers();
            let peers = peers.read();
            assert!(!peers.is_empty());
        };

        {
            let network = network1_c.lock();
            let peers = network.peers();
            let peers = peers.read();
            assert!(!peers.is_empty());
        };
    }

    quickcheck! {
        fn serialize_deserialize(packet: Arc<Ping>) -> bool {
            packet == Ping::from_bytes(&Ping::to_bytes(&packet)).unwrap()
        }
    }
}
