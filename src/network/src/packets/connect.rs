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
use byteorder::{ReadBytesExt, WriteBytesExt};
use crypto::NodeId;
use crypto::{KxPublicKey as KxPk, PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct Connect {
    node_id: NodeId,
    kx_key: KxPk,
    signature: Option<Signature>,
}

impl Connect {
    pub fn new(node_id: NodeId, kx_key: KxPk) -> Connect {
        Connect {
            node_id: node_id,
            kx_key: kx_key,
            signature: None,
        }
    }

    pub fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    pub fn verify_sig(&self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.node_id.0),
            None => false,
        }
    }
}

impl Packet for Connect {
    const PACKET_TYPE: u8 = 1;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let packet_type: u8 = Self::PACKET_TYPE;
        let signature = if let Some(signature) = &self.signature {
            signature.inner_bytes()
        } else {
            panic!("Signature field is missing");
        };

        let node_id = &self.node_id.0;
        let kx_key = &self.kx_key.0;

        // Connect packet structure:
        // 1) Packet type(1)   - 8bits
        // 2) Key exchange pk  - 32byte binary
        // 3) Node id          - 32byte binary
        // 4) Signature        - 64byte binary
        buffer.write_u8(packet_type).unwrap();
        buffer.extend_from_slice(kx_key);
        buffer.extend_from_slice(&node_id.0);
        buffer.extend_from_slice(&signature);
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

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..1).collect();

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

            NodeId(Pk(b))
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let signature = if buf.len() == 64 as usize {
            Signature::new(&buf)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = Connect {
            node_id,
            kx_key,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &Connect,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        if !packet.verify_sig() {
            return Err(NetworkErr::BadSignature);
        }

        let our_node_id = network.our_node_id().clone();
        let node_id = packet.node_id.clone();

        // Avoid connecting to ourselves
        if our_node_id != node_id {
            let mut our_pk = None;

            {
                let peers = network.peers();
                let mut peers = peers.write();
                let node_id = node_id.clone();
                let kx_key = &packet.kx_key;
                let mut peer = if let Some(peer) = peers.get_mut(addr) {
                    peer
                } else {
                    return Err(NetworkErr::PeerNotFound);
                };

                // Compute session keys
                let result = match conn_type {
                    ConnectionType::Client => crypto::client_sk(&peer.pk, &peer.sk, kx_key),
                    ConnectionType::Server => crypto::server_sk(&peer.pk, &peer.sk, kx_key),
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
                
                // Fetch credentials
                our_pk = Some(peer.pk.clone());
            }

            // If we are the server, also send a connect packet back
            if let ConnectionType::Server = conn_type {
                debug!("Sending connect packet to {}", addr);
                let mut packet = Connect::new(our_node_id, our_pk.unwrap());
                packet.sign(network.secret_key());
                network.send_raw(addr, &packet.to_bytes())?;
            }

            Ok(())
        } else {
            Err(NetworkErr::SelfConnect)
        }
    }
}

fn assemble_message(obj: &Connect) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    let kx_key = obj.kx_key.0;
    let node_id = (obj.node_id.0).0;

    buf.extend_from_slice(&[Connect::PACKET_TYPE]);
    buf.extend_from_slice(&kx_key);
    buf.extend_from_slice(&node_id);

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

        Connect {
            node_id: NodeId(*id.pkey()),
            kx_key: pk,
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::interface::NetworkInterface;
    use crate::mock::MockNetwork;
    use crypto::NodeId;
    use hashbrown::HashMap;
    use parking_lot::Mutex;
    use std::sync::mpsc::channel;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn it_successfuly_performs_connect_handshake() {
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

        // Pause main thread for a bit before
        // making assertions.
        thread::sleep(Duration::from_millis(1600));

        let peer1 = {
            let network = network2_c.lock();
            let peers = network.peers();
            let peers = peers.read();
            peers.get(&addr1).unwrap().clone()
        };

        let peer2 = {
            let network = network1_c.lock();
            let peers = network.peers();
            let peers = peers.read();
            peers.get(&addr2).unwrap().clone()
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

        fn verify_signature(id1: Identity, id2: Identity) -> bool {
            let id = Identity::new();
            let (pk, _) = crypto::gen_kx_keypair();
            let mut packet = Connect {
                node_id: NodeId(*id.pkey()),
                kx_key: pk,
                signature: None,
            };

            packet.sign(&id.skey());
            packet.verify_sig()
        }

    }
}
