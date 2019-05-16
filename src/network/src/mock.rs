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

use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::packets::connect::Connect;
use crate::peer::{Peer, ConnectionType};
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::VecDeque;
use crypto::SecretKey as Sk;
use hashbrown::HashMap;
use parking_lot::Mutex;
use NodeId;

#[derive(Debug, Clone)]
pub struct MockNetwork {
    /// Mapping between node ids and their mailboxes
    /// An entry in the mailbox is a tuple of two elements
    /// containing the sender's address and the received packet.
    mailboxes: Arc<Mutex<HashMap<NodeId, VecDeque<(SocketAddr, Vec<u8>)>>>>,

    /// Mapping between ips and node ids.
    address_mappings: HashMap<SocketAddr, NodeId>, 

    /// Mapping between connected peers and their information
    pub(crate) peers: HashMap<SocketAddr, Peer>,

    /// Our ip
    ip: SocketAddr,

    /// Our node id
    node_id: NodeId,

    /// Our secret key
    secret_key: Sk,

    /// The name of the network we are on
    network_name: String,
}

impl NetworkInterface for MockNetwork {
    fn connect(&mut self, address: &SocketAddr) -> Result<(), NetworkErr> {
        let (pk, sk) = crypto::gen_kx_keypair();
        let mut connect_packet = Connect::new(self.node_id.0, pk.clone());
        connect_packet.sign(self.secret_key.clone()); 
        let connect = connect_packet.to_bytes();
        let mut peer = Peer::new(None, address.clone(), ConnectionType::Client);
        peer.sent_connect = true;
        self.peers.insert(address.clone(), peer);

        let id = self.address_mappings.get(address).unwrap();
        self.send_to_peer(id, &connect).unwrap();

        Ok(())
    }

    fn connect_to_known(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn disconnect(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn disconnect_from_ip(&self, ip: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_peer(&self, peer: &NodeId, packet: &[u8]) -> Result<(), NetworkErr> {
        let mut mailboxes = self.mailboxes.lock();

        if let Some(mailbox) = mailboxes.get_mut(peer) {
            mailbox.push_front((self.ip.clone(), packet.to_vec()));
            Ok(())
        } else {
            Err(NetworkErr::PeerNotFound)
        }
    }

    fn send_to_all(&self, packet: &[u8]) -> Result<(), NetworkErr> {
        let mut mailboxes = self.mailboxes.lock();

        if mailboxes.is_empty() {
            return Err(NetworkErr::NoPeers);
        }

        for (_, mailbox) in mailboxes.iter_mut() {
            mailbox.push_front((self.ip.clone(), packet.to_vec()));
        }

        Ok(())
    }

    fn process_packet(&mut self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        // Insert to peer table if this is the first received packet.
        if self.peers.get(peer).is_none() {
            self.peers.insert(peer.clone(), Peer::new(None, peer.clone(), ConnectionType::Server));
        }
        
        // We should receive a connect packet
        // if the peer's id is non-existent.
        if self.peers.get(peer).unwrap().id.is_none() {
            match Connect::from_bytes(packet) {
                Ok(connect_packet) => {
                    debug!(
                        "Received connect packet from {}: {:?}",
                        peer, connect_packet
                    );

                    Ok(())
                }
                _ => {
                    // Invalid packet, remove peer
                    debug!("Invalid connect packet from {}", peer);
                    Err(NetworkErr::InvalidConnectPacket)
                }
            }
        } else {
            info!("{}: {}", peer, hex::encode(packet));
            Ok(())
        }
    }

    fn ban_peer(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn ban_ip(&self, peer: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

impl MockNetwork {
    pub fn new(node_id: NodeId, ip: SocketAddr, network_name: String, secret_key: Sk, mailboxes: Arc<Mutex<HashMap<NodeId, VecDeque<(SocketAddr, Vec<u8>)>>>>, address_mappings: HashMap<SocketAddr, NodeId>) -> MockNetwork {
        MockNetwork {
            mailboxes,
            address_mappings,
            peers: HashMap::new(),
            node_id,
            secret_key,
            ip,
            network_name
        }
    }

    pub fn start_receive_loop(network: Arc<Mutex<Self>>) {
        loop {
            let mut network = network.lock();
            let mailboxes = network.mailboxes.clone();
            let mut mailboxes = mailboxes.lock();
            let inbound_buf = mailboxes.get_mut(&network.node_id).unwrap();

            if let Some((addr, packet)) = inbound_buf.pop_back() {
                if let Err(err) = network.process_packet(&addr, &packet) {
                    match err {
                        NetworkErr::InvalidConnectPacket =>  {
                            network.disconnect_from_ip(&addr).unwrap();
                            network.ban_ip(&addr).unwrap();
                        },
                        _ => { }
                    }
                }
            }
        }
    }
}
