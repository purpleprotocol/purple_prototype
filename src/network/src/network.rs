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
use crate::packets::connect::Connect;
use chain::*;
use crypto::NodeId;
use crypto::SecretKey as Sk;
use hashbrown::{HashMap, HashSet};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use Peer;

#[cfg(test)]
use std::sync::mpsc::Sender;

#[cfg(not(test))]
use futures::sync::mpsc::Sender;

pub struct Network {
    /// Mapping between connected ips and peer information
    pub(crate) peers: HashMap<SocketAddr, Peer>,

    /// Our node id
    pub(crate) node_id: NodeId,

    /// Our secret key
    pub(crate) secret_key: Sk,

    /// Reference to the `EasyChain`
    easy_chain_ref: EasyChainRef,

    /// Reference to the `HardChain`
    hard_chain_ref: HardChainRef,

    /// Reference to the `StateChain`
    state_chain_ref: StateChainRef,

    /// Sender to `StateChain` block buffer
    state_chain_sender: Sender<(SocketAddr, Arc<StateBlock>)>,

    /// Sender to `HardChain` block buffer
    hard_chain_sender: Sender<(SocketAddr, Arc<HardBlock>)>,

    /// Sender to `EasyChain` block buffer
    easy_chain_sender: Sender<(SocketAddr, Arc<EasyBlock>)>,

    /// The name of the network we are on
    network_name: String,

    /// Maximum number of allowed peers, default is 8
    pub(crate) max_peers: usize,
}

impl Network {
    pub fn new(
        node_id: NodeId,
        network_name: String,
        secret_key: Sk,
        max_peers: usize,
        easy_chain_sender: Sender<(SocketAddr, Arc<EasyBlock>)>,
        hard_chain_sender: Sender<(SocketAddr, Arc<HardBlock>)>,
        state_chain_sender: Sender<(SocketAddr, Arc<StateBlock>)>,
        easy_chain_ref: EasyChainRef,
        hard_chain_ref: HardChainRef,
        state_chain_ref: StateChainRef,
    ) -> Network {
        Network {
            peers: HashMap::with_capacity(max_peers),
            node_id,
            network_name,
            secret_key,
            max_peers,
            easy_chain_sender,
            hard_chain_sender,
            state_chain_sender,
            easy_chain_ref,
            hard_chain_ref,
            state_chain_ref,
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr, peer: Peer) -> Result<(), NetworkErr> {
        if self.peer_count() < self.max_peers {
            self.peers.insert(addr, peer);
            Ok(())
        } else {
            Err(NetworkErr::MaximumPeersReached)
        }
    }

    /// Returns the number of listed peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns a reference to the stored secret key.
    pub fn skey(&self) -> &Sk {
        &self.secret_key
    }

    /// Sets the node id of the peer with the given address.
    ///
    /// This function will panic if there is no entry for the given address.
    pub fn set_node_id(&mut self, addr: &SocketAddr, node_id: NodeId) {
        match self.peers.get_mut(addr) {
            Some(peer) => peer.set_id(node_id),
            None => panic!("There is no listed peer with the given address!"),
        };
    }

    /// Removes the peer entry with the given address.
    pub fn remove_peer_with_addr(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }

    /// Returns true if the peer with the given address has a `None` id field.
    ///
    /// This function will panic if there is no entry for the given address.
    pub fn is_none_id(&self, addr: &SocketAddr) -> bool {
        match self.peers.get(addr) {
            Some(peer) => peer.id.is_none(),
            None => panic!("There is no listed peer with the given address!"),
        }
    }
}

impl NetworkInterface for Network {
    fn connect(&mut self, address: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn connect_to_known(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn is_connected_to(&self, address: &SocketAddr) -> bool {
        self.peers.get(address).is_some()
    }

    fn disconnect(&mut self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn disconnect_from_ip(&mut self, ip: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_peer(&self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_all(&self, packet: &[u8]) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_all_except(&self, exception: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_all_unsigned_except<P: Packet>(
        &self,
        exception: &SocketAddr,
        packet: &mut P,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_all_unsigned<P: Packet>(&self, packet: &mut P) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_raw(&self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_unsigned<P: Packet>(
        &self,
        peer: &SocketAddr,
        packet: &mut P,
    ) -> Result<(), NetworkErr> {
        if packet.signature().is_none() {
            packet.sign(&self.secret_key);
        }

        let packet = packet.to_bytes();
        self.send_to_peer(peer, &packet)?;

        Ok(())
    }

    fn send_raw_unsigned<P: Packet>(
        &self,
        peer: &SocketAddr,
        packet: &mut P,
    ) -> Result<(), NetworkErr> {
        if packet.signature().is_none() {
            packet.sign(&self.secret_key);
        }

        let packet = packet.to_bytes();
        self.send_raw(peer, &packet)?;

        Ok(())
    }

    fn easy_chain_ref(&self) -> EasyChainRef {
        self.easy_chain_ref.clone()
    }

    fn hard_chain_ref(&self) -> HardChainRef {
        self.hard_chain_ref.clone()
    }

    fn state_chain_ref(&self) -> StateChainRef {
        self.state_chain_ref.clone()
    }

    fn easy_chain_sender(&self) -> &Sender<(SocketAddr, Arc<EasyBlock>)> {
        &self.easy_chain_sender
    }

    fn hard_chain_sender(&self) -> &Sender<(SocketAddr, Arc<HardBlock>)> {
        &self.hard_chain_sender
    }

    fn state_chain_sender(&self) -> &Sender<(SocketAddr, Arc<StateBlock>)> {
        &self.state_chain_sender
    }

    fn process_packet(&mut self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        let (is_none_id, conn_type) = {
            let peer = self.peers.get(peer).unwrap();
            (peer.id.is_none(), peer.connection_type)
        };

        // We should receive a connect packet
        // if the peer's id is non-existent.
        if is_none_id {
            match Connect::from_bytes(packet) {
                Ok(connect_packet) => {
                    debug!(
                        "Received connect packet from {}: {:?}",
                        peer, connect_packet
                    );

                    // Handle connect packet
                    Connect::handle(self, peer, &connect_packet, conn_type)?;

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
