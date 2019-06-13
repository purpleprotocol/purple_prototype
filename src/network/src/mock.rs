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
use crate::packets::*;
use crate::peer::{Peer, ConnectionType};
use crate::packet::Packet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::VecDeque;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Sender, Receiver};
use chain::{HardChainRef, EasyChainRef, HardBlock, EasyBlock};
use crypto::SecretKey as Sk;
use hashbrown::HashMap;
use parking_lot::Mutex;
use NodeId;

#[derive(Debug)]
/// Mock network layer used for testing.
pub struct MockNetwork {
    /// Mapping between node ids and their mailboxes
    /// An entry in the mailbox is a tuple of two elements
    /// containing the sender's address and the received packet.
    mailboxes: HashMap<NodeId, Sender<(SocketAddr, Vec<u8>)>>,

    /// Our receiver
    rx: Receiver<(SocketAddr, Vec<u8>)>,

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
        info!("Connecting to {:?}", address);

        let mut peer = Peer::new(None, address.clone(), ConnectionType::Client);
        let mut connect_packet = Connect::new(self.node_id.clone(), peer.pk.clone());
        connect_packet.sign(&self.secret_key); 
        let connect = connect_packet.to_bytes();
        
        peer.sent_connect = true;
        self.peers.insert(address.clone(), peer);
        self.send_raw(address, &connect).unwrap();

        Ok(())
    }

    fn connect_to_known(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn is_connected_to(&self, address: &SocketAddr) -> bool {
        self.peers.get(address).is_some()
    }

    fn disconnect(&mut self, peer: &NodeId) -> Result<(), NetworkErr> {
        self.peers.retain(|_, p| p.id.as_ref() != Some(peer));
        Ok(())
    }

    fn disconnect_from_ip(&mut self, ip: &SocketAddr) -> Result<(), NetworkErr> {
        self.peers.remove(ip);
        Ok(())
    }

    fn send_to_peer(&self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        let id = if let Some(id) = self.address_mappings.get(peer) {
            id
        } else {
            return Err(NetworkErr::PeerNotFound);
        };

        if let Some(mailbox) = self.mailboxes.get(&id) {
            let peer = self.peers.get(peer).unwrap();
            let key = peer.rx.as_ref().unwrap();
            let packet = crate::common::wrap_packet(packet, key);
            mailbox.send((self.ip.clone(), packet)).unwrap();
            Ok(())
        } else {
            Err(NetworkErr::PeerNotFound)
        }
    }

    fn send_raw(&self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        let id = if let Some(id) = self.address_mappings.get(peer) {
            id
        } else {
            return Err(NetworkErr::PeerNotFound);
        };
        
        if let Some(mailbox) = self.mailboxes.get(&id) {
            mailbox.send((self.ip.clone(), packet.to_vec())).unwrap();
            Ok(())
        } else {
            Err(NetworkErr::PeerNotFound)
        }
    }

    fn send_to_all(&self, packet: &[u8]) -> Result<(), NetworkErr> {
        if self.mailboxes.is_empty() {
            return Err(NetworkErr::NoPeers);
        }

        for (_, mailbox) in self.mailboxes.iter() {
            mailbox.send((self.ip.clone(), packet.to_vec())).unwrap();
        }

        Ok(())
    }

    fn send_unsigned<P: Packet>(&self, peer: &SocketAddr, packet: &mut P) -> Result<(), NetworkErr> {
        if packet.signature().is_none() {
            packet.sign(&self.secret_key);
        }

        let packet = packet.to_bytes();
        self.send_to_peer(peer, &packet)?;

        Ok(())
    }

    fn send_raw_unsigned<P: Packet>(&self, peer: &SocketAddr, packet: &mut P) -> Result<(), NetworkErr> {
        if packet.signature().is_none() {
            packet.sign(&self.secret_key);
        }

        let packet = packet.to_bytes();
        self.send_raw(peer, &packet)?;

        Ok(())
    }

    fn easy_chain_ref(&self) -> EasyChainRef {
        unimplemented!();
    }

    fn hard_chain_ref(&self) -> HardChainRef {
        unimplemented!();
    }

    fn easy_chain_sender(&self) -> &Sender<Arc<EasyBlock>> {
        unimplemented!();
    }

    fn hard_chain_sender(&self) -> &Sender<Arc<HardBlock>> {
        unimplemented!();
    }

    fn process_packet(&mut self, addr: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        if addr == &self.ip {
            panic!("We received a packet from ourselves! This is illegal");
        }

        // Insert to peer table if this is the first received packet.
        if self.peers.get(addr).is_none() {
            self.peers.insert(addr.clone(), Peer::new(None, addr.clone(), ConnectionType::Server));
        }

        let (tx, is_none_id, conn_type) = {
            let peer = self.peers.get(addr).unwrap();
            (peer.tx.clone(), peer.id.is_none(), peer.connection_type)
        };

        // We should receive a connect packet
        // if the peer's id is non-existent.
        if is_none_id {
            match Connect::from_bytes(packet) {
                Ok(connect_packet) => {
                    debug!(
                        "Received connect packet from {}: {:?}",
                        addr, connect_packet
                    );

                    // Handle connect packet
                    Connect::handle(self, addr, &connect_packet, conn_type)?;

                    Ok(())
                }
                _ => {
                    // Invalid packet, remove peer
                    debug!("Invalid connect packet from {}", addr);
                    Err(NetworkErr::InvalidConnectPacket)
                }
            }
        } else {
            debug!("Received packet from {}: {}", addr, hex::encode(packet));

            let packet = crate::common::unwrap_packet(packet, tx.as_ref().unwrap())?;
            let packet_type = packet[0];
            
            match packet_type {
                RequestPeers::PACKET_TYPE => match RequestPeers::from_bytes(&packet) {
                    Ok(packet) => RequestPeers::handle(self, addr, &packet, conn_type)?,
                    _ => return Err(NetworkErr::PacketParseErr)
                }
                    
                SendPeers::PACKET_TYPE => match SendPeers::from_bytes(&packet) {
                    Ok(packet) => SendPeers::handle(self, addr, &packet, conn_type)?,
                    _ => return Err(NetworkErr::PacketParseErr)
                }

                _ => {
                    debug!("Could not parse packet from {}", addr);
                    return Err(NetworkErr::PacketParseErr);
                }
            }

            Ok(())
        }
    }

    fn ban_peer(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn ban_ip(&self, peer: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn fetch_peer(&self, peer: &SocketAddr) -> Result<&Peer, NetworkErr> {
        if let Some(peer) = self.peers.get(peer) {
            Ok(peer)
        } else {
            Err(NetworkErr::PeerNotFound)        
        }
    }

    fn fetch_peer_mut(&mut self, peer: &SocketAddr) -> Result<&mut Peer, NetworkErr> {
        if let Some(peer) = self.peers.get_mut(peer) {
            Ok(peer)
        } else {
            Err(NetworkErr::PeerNotFound)        
        }
    }

    fn our_node_id(&self) -> &NodeId {
        &self.node_id
    }

    fn peers<'a>(&'a self) -> Box<dyn Iterator<Item = (&SocketAddr, &Peer)> + 'a> {
        Box::new(self.peers.iter())
    }
}

impl MockNetwork {
    pub fn new(
        node_id: NodeId, 
        ip: SocketAddr, 
        network_name: String, 
        secret_key: Sk, 
        rx: Receiver<(SocketAddr, Vec<u8>)>, 
        mailboxes: HashMap<NodeId, Sender<(SocketAddr, Vec<u8>)>>, 
        address_mappings: HashMap<SocketAddr, NodeId>
    ) -> MockNetwork {
        MockNetwork {
            rx,
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

            if let Ok((addr, packet)) = network.rx.try_recv() {
                if let Err(err) = network.process_packet(&addr, &packet) {
                    match err {
                        NetworkErr::InvalidConnectPacket =>  {
                            network.disconnect_from_ip(&addr).unwrap();
                            network.ban_ip(&addr).unwrap();
                        },
                        err => { 
                            debug!("Packet error: {:?}", err);
                        }
                    }
                }
            }
        }
    }
}
