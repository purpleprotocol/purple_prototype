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
use std::net::SocketAddr;
use std::sync::Arc;
use std::str;
use chrono::prelude::*;
use byteorder::{ReadBytesExt, WriteBytesExt};
use crypto::{PublicKey as Pk, ExpandedSecretKey as Sk, Signature, KxPublicKey as KxPk};
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq)]
pub struct Connect {
    node_id: NodeId,
    kx_key: KxPk,
    timestamp: DateTime<Utc>,
    signature: Option<Signature>,
}

impl Connect {
    pub const PACKET_TYPE: u8 = 1;

    pub fn new(node_id: NodeId, kx_key: KxPk) -> Connect {
        Connect {
            node_id: node_id,
            kx_key: kx_key,
            timestamp: Utc::now(),
            signature: None,
        }
    }
}

impl Packet for Connect {
    fn sign(&mut self, skey: &Sk, pkey: &Pk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign_expanded(&message, skey, pkey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    fn verify_sig(&self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.node_id.to_pkey()),
            None => false,
        }
    }

    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
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
        let kx_key = &self.kx_key.0;

        // Connect packet structure:
        // 1) Packet type(1)   - 8bits
        // 2) Timestamp length - 8bits
        // 3) Key exchange pk  - 32byte binary
        // 4) Node id          - 32byte binary
        // 5) Signature        - 64byte binary
        // 6) Timestamp        - Binary of timestamp length
        buffer.write_u8(packet_type).unwrap();
        buffer.write_u8(timestamp_length).unwrap();
        buffer.extend_from_slice(kx_key);
        buffer.extend_from_slice(node_id);
        buffer.extend_from_slice(&signature);
        buffer.extend_from_slice(timestamp.as_bytes());

        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<Connect>, NetworkErr> {
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

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..2).collect();

        let kx_key = if buf.len() > 32 as usize {
            let kx_key_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&kx_key_vec);

            KxPk(b)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let node_id = if buf.len() > 32 as usize {
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&node_id_vec);
            let is_valid_pk = Pk::from_bytes(&b).is_ok();

            if is_valid_pk {
                NodeId(b)
            } else {
                return Err(NetworkErr::BadFormat);
            }
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();
            Signature::new(&sig_vec)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let timestamp = if buf.len() == timestamp_len as usize {
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

        let packet = Connect {
            node_id,
            kx_key,
            timestamp,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn handle<N: NetworkInterface>(network: &mut N, addr: &SocketAddr, packet: &Connect, conn_type: ConnectionType) -> Result<(), NetworkErr> {
        let our_node_id = network.our_node_id().clone();
        let node_id = packet.node_id.clone();
        let mut our_pk = None;
        
        {
            let node_id = node_id.clone();
            let peer = network.fetch_peer_mut(addr)?;
            let kx_key = packet.kx_key.clone();

            // Compute session keys
            let result = match conn_type {
                ConnectionType::Client => {
                    crypto::client_sk(&peer.pk, &peer.sk, &kx_key)
                }
                ConnectionType::Server => {
                    crypto::server_sk(&peer.pk, &peer.sk, &kx_key)
                }
            };

            let (rx, tx) = if let Ok(result) = result {
                result
            } else {
                return Err(NetworkErr::InvalidConnectPacket);
            };

            // Set generated session keys
            peer.rx = Some(rx);
            peer.tx = Some(tx);

            // Mark peer as having sent a connect packet
            peer.sent_connect = true;

            // Set node id
            peer.id = Some(node_id);

            our_pk = Some(peer.pk.clone());
        }

        // If we are the server, also send a connect packet back
        if let ConnectionType::Server = conn_type {
            let mut packet = Connect::new(our_node_id,  our_pk.unwrap());
            network.send_unsigned::<Connect>(&node_id, &mut packet)?;
        }

        Ok(())
    }
}

fn assemble_message(obj: &Connect) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    let kx_key = obj.kx_key.0;
    let node_id = obj.node_id.0;
    let timestamp = obj.timestamp.to_rfc3339();

    buf.extend_from_slice(&[Connect::PACKET_TYPE]);
    buf.extend_from_slice(&kx_key);
    buf.extend_from_slice(&node_id);
    buf.extend_from_slice(timestamp.as_bytes());

    buf
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for Connect {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Connect {
        let (pk, _) = crypto::gen_kx_keypair();
        let id = Identity::new();
        let timestamp = Utc::now();

        Connect {
            node_id: NodeId::from_pkey(*id.pkey()),
            kx_key: pk,
            timestamp,
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::sync::mpsc::channel;
    use parking_lot::Mutex;
    use hashbrown::HashMap;
    use blake2::Blake2b;
    use crate::interface::NetworkInterface;
    use crate::mock::MockNetwork;
    use crate::node_id::NodeId;

    #[test]
    fn it_successfuly_performs_connect_handshake() {
        let mut mailboxes = HashMap::new();
        let addr1 = crate::random_socket_addr();
        let addr2 = crate::random_socket_addr();
        let (pk1, sk1) = crypto::gen_keypair();
        let (pk2, sk2) = crypto::gen_keypair(); 
        let sk1 = sk1.expand::<Blake2b>();
        let sk2 = sk2.expand::<Blake2b>();
        let n1 = NodeId::from_pkey(pk1);
        let n2 = NodeId::from_pkey(pk2);

        let (rx1, tx1) = channel();
        let (rx2, tx2) = channel();

        let mut address_mappings = HashMap::new();

        address_mappings.insert(addr1.clone(), n1.clone());
        address_mappings.insert(addr2.clone(), n2.clone());

        mailboxes.insert(n1.clone(), rx1);
        mailboxes.insert(n2.clone(), rx2);

        let network1 = MockNetwork::new(n1.clone(), addr1, "test_network".to_owned(), sk1, tx1, mailboxes.clone(), address_mappings.clone());
        let network2 = MockNetwork::new(n2.clone(), addr2, "test_network".to_owned(), sk2, tx2, mailboxes.clone(), address_mappings.clone());
        let network1 = Arc::new(Mutex::new(network1));
        let network1_c = network1.clone();
        let network2 = Arc::new(Mutex::new(network2));
        let network2_c = network2.clone();

        // Peer 1 listener thread
        thread::Builder::new()
            .name("peer1".to_string())
            .spawn(move || MockNetwork::start_receive_loop(network1))
            .unwrap();

        // Peer 2 listener thread
        thread::Builder::new()
            .name("peer2".to_string())
            .spawn(move || MockNetwork::start_receive_loop(network2))
            .unwrap();

        {
            // Attempt to connect the first peer to the second
            network1_c.lock().connect(&addr2).unwrap();
        }

        // Pause main thread for a bit before
        // making assertions.
        thread::sleep(Duration::from_millis(100));

        let peer1 = {
            let network2 = network2_c.lock();
            network2.peers.get(&addr1).unwrap().clone()
        };

        let peer2 = {
            let network1 = network1_c.lock();
            network1.peers.get(&addr2).unwrap().clone()
        };
        
        // Check if the peers have the same session keys
        assert_eq!(peer1.rx.as_ref().unwrap(), peer2.tx.as_ref().unwrap());
        assert_eq!(peer2.rx.as_ref().unwrap(), peer1.tx.as_ref().unwrap());

        // Check if the peers have the correct node ids
        assert_eq!(peer1.id.unwrap(), n1);
        assert_eq!(peer2.id.unwrap(), n2);
    }

    quickcheck! {
        fn serialize_deserialize(tx: Arc<Connect>) -> bool {
            tx == Connect::from_bytes(&Connect::to_bytes(&tx)).unwrap()
        }

        fn verify_signature() -> bool {
            let id = Identity::new();
            let sk = id.skey().expand::<Blake2b>();
            let (pk, _) = crypto::gen_kx_keypair();
            let timestamp = Utc::now();
            let mut packet = Connect {
                node_id: NodeId::from_pkey(*id.pkey()),
                kx_key: pk,
                signature: None,
                timestamp
            };

            packet.sign(&sk, id.pkey());
            packet.verify_sig()
        }

    }
}
