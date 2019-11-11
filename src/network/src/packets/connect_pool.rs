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
use crypto::{NodeId, Hash, KxPublicKey as KxPk, PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
/// A `ConnectPool` packet is used by a successful miner
/// to connect to a validator pool.
pub struct ConnectPool {
    node_id: NodeId,
    pow_block_hash: Hash,
    kx_key: KxPk,
    signature: Option<Signature>,
}

impl ConnectPool {
    pub fn new(node_id: NodeId, kx_key: KxPk, pow_block_hash: Hash) -> ConnectPool {
        ConnectPool {
            node_id,
            kx_key,
            pow_block_hash,
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

impl Packet for ConnectPool {
    const PACKET_TYPE: u8 = 7;

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

        // ConnectPool packet structure:
        // 1) Packet type(7)   - 8bits
        // 2) Key exchange pk  - 32byte binary
        // 3) Node id          - 32byte binary
        // 4) Pow block hash   - 32byte binary
        // 5) Signature        - 64byte binary
        buffer.write_u8(packet_type).unwrap();
        buffer.extend_from_slice(kx_key);
        buffer.extend_from_slice(&node_id.0);
        buffer.extend_from_slice(&self.pow_block_hash.0);
        buffer.extend_from_slice(&signature);
        buffer
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<ConnectPool>, NetworkErr> {
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

        let pow_block_hash = if buf.len() > 32 as usize {
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&node_id_vec);

            Hash(b)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let signature = if buf.len() == 64 as usize {
            Signature::new(&buf)
        } else {
            return Err(NetworkErr::BadFormat);
        };

        let packet = ConnectPool {
            node_id,
            pow_block_hash,
            kx_key,
            signature: Some(signature),
        };

        Ok(Arc::new(packet))
    }

    #[cfg(not(feature = "miner"))]
    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &ConnectPool,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unreachable!();
    }

    #[cfg(feature = "miner")]
    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &ConnectPool,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        let pool_network = {
            let pool_ref = network.validator_pool_network_ref();
            let pool_ref = pool_ref.read();
            (*pool_ref).clone().ok_or(NetworkErr::NoPoolSession)?
        };

        // Verify packet signature
        if !packet.verify_sig() {
            return Err(NetworkErr::BadSignature);
        }

        let our_node_id = network.our_node_id().clone();
        let node_id = packet.node_id.clone();

        // Avoid connecting to ourselves
        if our_node_id != node_id {
            let mut our_pk = None;

            {
                let node_id = node_id.clone();
                let kx_key = &packet.kx_key;

                // Remove peer entry from default network interface
                let mut peer = {
                    let peers = network.peers();
                    let mut peers = peers.write();
                    peers.remove(addr).ok_or(NetworkErr::PeerNotFound)?
                };

                // Compute session keys
                let result = match conn_type {
                    ConnectionType::Client(_) => crypto::client_sk(&peer.pk, &peer.sk, kx_key),
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

                // Map peer entry to validator entry
                let peer = peer.to_validator();

                // Store validator entry
                let mut pool_peers = pool_network.peers.write();
                pool_peers.insert(addr.clone(), peer);
            }

            // If we are the server, also send a connect packet back
            if let ConnectionType::Server = conn_type {
                debug!("Sending connect pool packet to {}", addr);
                let mut packet = ConnectPool::new(our_node_id, our_pk.unwrap(), pool_network.start_pow_block);
                packet.sign(network.secret_key());
                network.send_raw(addr, &packet.to_bytes())?;
            }

            // Execute after connect callback
            network.after_connect(addr);

            Ok(())
        } else {
            Err(NetworkErr::SelfConnect)
        }
    }
}

fn assemble_message(obj: &ConnectPool) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    let kx_key = obj.kx_key.0;
    let node_id = (obj.node_id.0).0;

    buf.extend_from_slice(&[ConnectPool::PACKET_TYPE]);
    buf.extend_from_slice(&kx_key);
    buf.extend_from_slice(&obj.pow_block_hash.0);
    buf.extend_from_slice(&node_id);

    buf
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for ConnectPool {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ConnectPool {
        let (pk, _) = crypto::gen_kx_keypair();
        let id = Identity::new();

        ConnectPool {
            node_id: NodeId(*id.pkey()),
            pow_block_hash: Arbitrary::arbitrary(g),
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
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    quickcheck! {
        fn serialize_deserialize(tx: Arc<ConnectPool>) -> bool {
            tx == ConnectPool::from_bytes(&ConnectPool::to_bytes(&tx)).unwrap()
        }

        fn verify_signature(id1: Identity, id2: Identity) -> bool {
            let id = Identity::new();
            let (pk, _) = crypto::gen_kx_keypair();
            let mut packet = ConnectPool {
                node_id: NodeId(*id.pkey()),
                kx_key: pk,
                pow_block_hash: crypto::hash_slice(b""),
                signature: None,
            };

            packet.sign(&id.skey());
            packet.verify_sig()
        }

    }
}
