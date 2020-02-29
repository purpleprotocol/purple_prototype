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
use crate::validation::sender::Sender;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rlp::{Rlp, RlpStream};
use std::io::Cursor;
use std::net::SocketAddr;
use std::str;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct SendPeers {
    /// Randomly generated nonce
    pub(crate) nonce: u64,

    /// The list of peers to be sent
    pub(crate) peers: Vec<SocketAddr>,
}

impl SendPeers {
    pub fn new(peers: Vec<SocketAddr>, nonce: u64) -> SendPeers {
        SendPeers { peers, nonce }
    }

    fn encode_peers(&self) -> Vec<u8> {
        let mut encoder = RlpStream::new_list(self.peers.len());

        // Encode peers with RLP
        for peer in self.peers.iter() {
            let formatted = format!("{}", peer);
            encoder.append(&formatted);
        }

        encoder.out()
    }
}

impl Packet for SendPeers {
    const PACKET_TYPE: u8 = 5;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;
        let peers = self.encode_peers();
        let peers_len = peers.len();

        // Packet structure:
        // 1) Packet type(5)   - 8bits
        // 2) Peers length     - 16bits
        // 3) Nonce            - 64bits
        // 4) Peers            - Binary of peers length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u16::<BigEndian>(peers_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(self.nonce).unwrap();
        buffer.extend_from_slice(&peers);
        buffer
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<SendPeers>, NetworkErr> {
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

        let peers_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
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

        let peers = if buf.len() == peers_len as usize {
            let rlp = Rlp::new(&buf);
            let mut peers = Vec::new();

            if rlp.is_list() {
                for bytes in rlp.iter() {
                    if bytes.is_data() {
                        let data = bytes.data().map_err(|_| NetworkErr::BadFormat)?;
                        let data = str::from_utf8(&data).map_err(|_| NetworkErr::BadFormat)?;
                        let addr =
                            SocketAddr::from_str(&data).map_err(|_| NetworkErr::BadFormat)?;

                        peers.push(addr);
                    } else {
                        return Err(NetworkErr::BadFormat);
                    }
                }

                peers
            } else {
                return Err(NetworkErr::BadFormat);
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = SendPeers { nonce, peers };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &SendPeers,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        debug!(
            "Received SendPeers packet from {} with nonce {}",
            addr, packet.nonce
        );

        // Retrieve sender mutex
        let sender = {
            let peers = network.peers();
            let peers = peers.read();
            let peer = peers.get(addr).ok_or(NetworkErr::SessionExpired)?;

            peer.validator.request_peers.sender.clone()
        };

        debug!("Acking SendPeers {}", packet.nonce);

        // Ack packet
        {
            let mut sender = sender.lock();
            sender.acknowledge(packet)?;
        }

        debug!("SendPeers {} acked!", packet.nonce);

        // Attempt to connect to the received peers
        for addr in packet.peers.iter() {
            if network.is_connected_to(addr) {
                continue;
            }

            network
                .connect(addr)
                .map_err(|err| warn!("Could not connect to {}: {:?}", addr, err))
                .unwrap_or(());
        }

        Ok(())
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for SendPeers {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> SendPeers {
        SendPeers {
            nonce: Arbitrary::arbitrary(g),
            peers: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::interface::NetworkInterface;
    use crate::packets::RequestPeers;
    use crate::priority::NetworkPriority;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn it_sends_and_requests_peers() {
        let networks = crate::init_test_networks(5);
        let addr1 = networks[0].1;
        let addr2 = networks[1].1;
        let addr3 = networks[2].1;
        let addr4 = networks[3].1;
        let addr5 = networks[4].1;
        let network1 = networks[0].0.clone();
        let network1_cc = network1.clone();
        let network2 = networks[1].0.clone();
        let network2_c = network2.clone();
        let network2_cc = network2.clone();
        let network3 = networks[2].0.clone();
        let network3_c = network3.clone();
        let network3_cc = network3.clone();
        let network4 = networks[3].0.clone();
        let network4_c = network4.clone();
        let network4_cc = network4.clone();
        let network5 = networks[4].0.clone();
        let network5_c = network5.clone();
        let network5_cc = network5.clone();

        // Establish initial connections.
        //
        // Peers 3, 4 and 5 will establish a connection
        // to Peer1.
        //
        // After this, Peer 2 will connect to Peer 1 and ask
        // it for its peer list.
        {
            network3_c.lock().connect(&addr1).unwrap();
        }

        {
            network4_c.lock().connect(&addr1).unwrap();
        }

        {
            network5_c.lock().connect(&addr1).unwrap();
        }

        {
            network2_c.lock().connect(&addr1).unwrap();
        }

        thread::sleep(Duration::from_millis(1000));

        // Send request peers packet from Peer2 to Peer1
        {
            let mut network = network2_c.lock();
            let node_id = network.our_node_id().clone();
            let sender = {
                let peers = network.peers();
                let peers = peers.read();
                let peer = peers.get(&addr1).unwrap();

                peer.validator.request_peers.sender.clone()
            };

            let mut sender = sender.lock();
            let packet = sender.send(3).unwrap();
            network
                .send_to_peer(&addr1, packet.to_bytes(), NetworkPriority::Medium)
                .unwrap();
        }

        // Pause main thread for a bit before
        // making assertions.
        thread::sleep(Duration::from_millis(300));

        let network1 = network1_cc.lock();
        let network2 = network2_cc.lock();
        let network3 = network3_cc.lock();
        let network4 = network4_cc.lock();
        let network5 = network5_cc.lock();

        let peers1 = network1.peers();
        let peers2 = network2.peers();
        let peers3 = network3.peers();
        let peers4 = network4.peers();
        let peers5 = network5.peers();

        assert_eq!(peers1.read().len(), 4);
        assert_eq!(peers2.read().len(), 4);
        assert_eq!(peers3.read().len(), 2);
        assert_eq!(peers4.read().len(), 2);
        assert_eq!(peers5.read().len(), 2);
    }

    quickcheck! {
        fn serialize_deserialize(tx: Arc<SendPeers>) -> bool {
            tx == SendPeers::from_bytes(&SendPeers::to_bytes(&tx)).unwrap()
        }
    }
}
