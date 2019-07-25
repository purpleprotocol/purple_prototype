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
use chrono::prelude::*;
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use rlp::{Rlp, RlpStream};
use std::io::Cursor;
use std::net::SocketAddr;
use std::str;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct SendPeers {
    /// The node id of the sender
    node_id: NodeId,

    /// The packet's timestamp
    timestamp: DateTime<Utc>,

    /// The list of peers to be sent
    peers: Vec<SocketAddr>,

    /// Packet signature
    signature: Option<Signature>,
}

impl SendPeers {
    pub const PACKET_TYPE: u8 = 3;

    pub fn new(node_id: NodeId, peers: Vec<SocketAddr>) -> SendPeers {
        SendPeers {
            node_id: node_id,
            peers,
            timestamp: Utc::now(),
            signature: None,
        }
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
    fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    fn verify_sig(&self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.node_id.0),
            None => false,
        }
    }

    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
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
        let timestamp_len = timestamp.len() as u8;
        let node_id = &self.node_id.0;
        let peers = self.encode_peers();
        let peers_len = peers.len();

        // Packet structure:
        // 1) Packet type(3)   - 8bits
        // 2) Timestamp length - 8bits
        // 3) Peers length     - 16bits
        // 4) Node id          - 32byte binary
        // 5) Signature        - 64byte binary
        // 6) Timestamp        - Binary of timestamp length
        // 7) Peers            - Binary of peers length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(timestamp_len).unwrap();
        buffer.write_u16::<BigEndian>(peers_len as u16).unwrap();
        buffer.extend_from_slice(&node_id.0);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(timestamp.as_bytes());
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

        let timestamp_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        rdr.set_position(2);

        let peers_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err(NetworkErr::BadFormat);
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..4).collect();

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
                    _ => return Err(NetworkErr::BadFormat),
                },
                Err(_) => return Err(NetworkErr::BadFormat),
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let peers = if buf.len() == peers_len as usize {
            let mut rlp = Rlp::new(&buf);
            let mut peers = Vec::new();

            if rlp.is_list() {
                for bytes in rlp.iter() {
                    if bytes.is_data() {
                        match bytes.data() {
                            Ok(bytes) => match str::from_utf8(bytes) {
                                Ok(result) => match SocketAddr::from_str(result) {
                                    Ok(addr) => peers.push(addr),
                                    Err(_) => return Err(NetworkErr::BadFormat),
                                },
                                _ => return Err(NetworkErr::BadFormat),
                            },
                            _ => return Err(NetworkErr::BadFormat),
                        }
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

        let packet = SendPeers {
            node_id,
            timestamp,
            peers,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &SendPeers,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        if !packet.verify_sig() {
            return Err(NetworkErr::BadSignature);
        }

        debug!("Received SendPeers packet from: {:?}", addr);

        {
            let peer = network.fetch_peer_mut(addr)?;

            // Check if we have received more peers than we have asked
            if let Some(num_of_peers) = peer.requested_peers {
                if (num_of_peers as usize) <= packet.peers.len() {
                    peer.requested_peers = None;
                } else {
                    return Err(NetworkErr::TooManyPeers);
                }
            } else {
                return Err(NetworkErr::DidntAskForPeers);
            }
        }

        let peers: Vec<SocketAddr> = {
            packet
                .peers
                .iter()
                // Don't connect to peers that we are already connected to
                .filter(|addr| !network.is_connected_to(addr))
                .cloned()
                .collect()
        };

        // Attempt to connect to the received peers
        for addr in peers.iter() {
            network.connect(addr).unwrap();
        }

        Ok(())
    }
}

fn assemble_sign_message(obj: &SendPeers) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let node_id = (obj.node_id.0).0;
    let timestamp = obj.timestamp.to_rfc3339();
    let peers = obj.encode_peers();

    buf.extend_from_slice(&[SendPeers::PACKET_TYPE]);
    buf.extend_from_slice(&node_id);
    buf.extend_from_slice(timestamp.as_bytes());
    buf.extend_from_slice(&peers);

    buf
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for SendPeers {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> SendPeers {
        let id = Identity::new();
        let timestamp = Utc::now();

        SendPeers {
            node_id: NodeId(*id.pkey()),
            timestamp,
            peers: Arbitrary::arbitrary(g),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::NetworkInterface;
    use crate::mock::MockNetwork;
    use crate::packets::RequestPeers;
    use chain::*;
    use crypto::NodeId;
    use hashbrown::HashMap;
    use parking_lot::{Mutex, RwLock};
    use std::sync::mpsc::channel;
    use std::sync::Arc;
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

        thread::sleep(Duration::from_millis(1600));

        // Send request peers packet from Peer2 to Peer1
        {
            let mut network = network2_c.lock();
            let node_id = network.our_node_id().clone();

            let peer_id = {
                let peer = network.fetch_peer_mut(&addr1).unwrap();
                peer.requested_peers = Some(3);
                peer.id.as_ref().cloned().unwrap()
            };

            let mut packet = RequestPeers::new(node_id, 3);
            network
                .send_unsigned::<RequestPeers>(&addr1, &mut packet)
                .unwrap();
        }

        // Pause main thread for a bit before
        // making assertions.
        thread::sleep(Duration::from_millis(600));

        let network1 = network1_cc.lock();
        let network2 = network2_cc.lock();
        let network3 = network3_cc.lock();
        let network4 = network4_cc.lock();
        let network5 = network5_cc.lock();

        assert_eq!(network1.peers.len(), 4);
        assert_eq!(network2.peers.len(), 4);
        assert_eq!(network3.peers.len(), 2);
        assert_eq!(network4.peers.len(), 2);
        assert_eq!(network5.peers.len(), 2);
    }

    quickcheck! {
        fn serialize_deserialize(tx: Arc<SendPeers>) -> bool {
            tx == SendPeers::from_bytes(&SendPeers::to_bytes(&tx)).unwrap()
        }

        fn verify_signature(id1: Identity, id2: Identity, peers: Vec<SocketAddr>) -> bool {
            let id = Identity::new();
            let timestamp = Utc::now();
            let mut packet = SendPeers {
                node_id: NodeId(*id.pkey()),
                peers,
                signature: None,
                timestamp
            };

            packet.sign(&id.skey());
            packet.verify_sig()
        }

    }
}