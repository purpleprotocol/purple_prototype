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

use crate::pool_network::PoolNetwork;
use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::packet::Packet;
use crate::packets::connect::Connect;
use crate::packets::connect_pool::ConnectPool;
use crate::bootstrap::cache::BootstrapCache;
use crate::connection::*;
use crate::peer::{ConnectionType, SubConnectionType};
use chain::*;
use crypto::NodeId;
use crypto::SecretKey as Sk;
use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use Peer;

#[cfg(test)]
use std::sync::mpsc::Sender;

#[cfg(not(test))]
use futures::sync::mpsc::Sender;

#[derive(Clone)]
pub struct Network {
    /// Mapping between connected ips and peer information
    pub(crate) peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,

    /// Our node id
    pub(crate) node_id: NodeId,

    /// Our secret key
    pub(crate) secret_key: Sk,

    /// Reference to the `PowChain`
    pow_chain_ref: PowChainRef,

    /// Reference to the `StateChain`
    state_chain_ref: StateChainRef,

    /// Sender to `StateChain` block buffer
    state_chain_sender: Sender<(SocketAddr, Arc<StateBlock>)>,

    /// Sender to `PowChain` block buffer
    pow_chain_sender: Sender<(SocketAddr, Arc<PowBlock>)>,

    /// The port we are accepting external TCP connections on.
    port: u16,

    /// The name of the network we are on
    pub(crate) network_name: String,

    /// Maximum number of allowed peers, default is 8
    pub(crate) max_peers: usize,

    /// Bootstrap cache
    pub(crate) bootstrap_cache: BootstrapCache,

    /// Accept connections boolean reference
    pub(crate) accept_connections: Arc<AtomicBool>,

    #[cfg(feature = "miner")]
    /// Validator pool sub-network. This field is `None` if we
    /// are not in a validator pool.
    pub(crate) current_pool: Arc<RwLock<Option<PoolNetwork>>>,
}

impl Network {
    pub fn new(
        node_id: NodeId,
        port: u16,
        network_name: String,
        secret_key: Sk,
        max_peers: usize,
        pow_chain_sender: Sender<(SocketAddr, Arc<PowBlock>)>,
        state_chain_sender: Sender<(SocketAddr, Arc<StateBlock>)>,
        pow_chain_ref: PowChainRef,
        state_chain_ref: StateChainRef,
        bootstrap_cache: BootstrapCache,
        accept_connections: Arc<AtomicBool>,
    ) -> Network {
        Network {
            peers: Arc::new(RwLock::new(HashMap::with_capacity(max_peers))),
            node_id,
            port,
            network_name,
            secret_key,
            max_peers,
            pow_chain_sender,
            state_chain_sender,
            pow_chain_ref,
            state_chain_ref,
            bootstrap_cache,
            accept_connections,

            #[cfg(feature = "miner")]
            current_pool: Arc::new(RwLock::new(None)),
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr, peer: Peer) -> Result<(), NetworkErr> {
        if self.peer_count() < self.max_peers {
            self.peers.write().insert(addr, peer);
            Ok(())
        } else {
            Err(NetworkErr::MaximumPeersReached)
        }
    }

    /// Returns the number of listed peers.
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Returns a reference to the stored secret key.
    pub fn skey(&self) -> &Sk {
        &self.secret_key
    }

    /// Sets the node id of the peer with the given address.
    ///
    /// This function will panic if there is no entry for the given address.
    pub fn set_node_id(&self, addr: &SocketAddr, node_id: NodeId) {
        let mut peers = self.peers.write();

        match peers.get_mut(addr) {
            Some(peer) => peer.set_id(node_id),
            None => panic!("There is no listed peer with the given address!"),
        };
    }

    /// Removes the peer entry with the given address.
    pub fn remove_peer_with_addr(&self, addr: &SocketAddr) {
        self.peers.write().remove(addr);
    }

    /// Returns true if the peer with the given address has a `None` id field.
    ///
    /// This function will panic if there is no entry for the given address.
    pub fn is_none_id(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read();

        match peers.get(addr) {
            Some(peer) => peer.id.is_none(),
            None => panic!("There is no listed peer with the given address!"),
        }
    }
}

impl NetworkInterface for Network {
    fn connect(&mut self, address: &SocketAddr) -> Result<(), NetworkErr> {
        info!("Connecting to {}", address);

        connect_to_peer(
            self.clone(),
            self.accept_connections.clone(),
            address,
            SubConnectionType::Normal,
        );

        Ok(())
    }

    fn connect_to_known(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn is_connected_to(&self, address: &SocketAddr) -> bool {
        let peers = self.peers.read();
        peers.get(address).is_some()
    }

    fn disconnect(&mut self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn disconnect_from_ip(&mut self, ip: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn has_peer(&self, addr: &SocketAddr) -> bool {
        self.peers.read().get(addr).is_some()
    }

    fn has_peer_with_id(&self, id: &NodeId) -> bool {
        unimplemented!()
    }

    #[cfg(feature = "miner")]
    fn validator_pool_network_ref(&self) -> Arc<RwLock<Option<PoolNetwork>>> {
        self.current_pool.clone()
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn send_to_peer(&self, peer: &SocketAddr, packet: Vec<u8>) -> Result<(), NetworkErr> {
        let peers = self.peers.read();

        if let Some(peer) = peers.get(peer) {
            if let Some(ref rx) = peer.rx {
                let packet = crate::common::wrap_encrypt_packet(
                    &packet,
                    &self.secret_key,
                    rx,
                    self.network_name.as_str(),
                );
                peer.send_packet(packet)
            } else {
                Err(NetworkErr::CouldNotSend)
            }
        } else {
            Err(NetworkErr::PeerNotFound)
        }
    }

    fn send_to_all(&self, packet: &[u8]) -> Result<(), NetworkErr> {
        let peers = self.peers.read();

        if peers.is_empty() {
            return Err(NetworkErr::NoPeers);
        }

        for (addr, peer) in peers.iter() {
            if let Some(ref rx) = peer.rx {
                let packet = crate::common::wrap_encrypt_packet(
                    &packet,
                    &self.secret_key,
                    rx,
                    self.network_name.as_str(),
                );
                peer.send_packet(packet.to_vec())
                    .map_err(|err| warn!("Failed to send packet to {}! Reason: {:?}", addr, err))
                    .unwrap_or(());
            }
        }

        Ok(())
    }

    fn send_to_all_except(&self, exception: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        let peers = self.peers.read();

        if peers.is_empty() {
            return Err(NetworkErr::NoPeers);
        }

        let iter = peers.iter().filter(|(addr, _)| *addr != exception);

        for (addr, peer) in iter {
            if let Some(ref rx) = peer.rx {
                let packet = crate::common::wrap_encrypt_packet(
                    &packet,
                    &self.secret_key,
                    rx,
                    self.network_name.as_str(),
                );
                peer.send_packet(packet.to_vec())
                    .map_err(|err| warn!("Failed to send packet to {}! Reason: {:?}", addr, err))
                    .unwrap_or(());
            }
        }

        Ok(())
    }

    fn send_raw(&self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        let peers = self.peers.read();

        if let Some(peer) = peers.get(peer) {
            let packet = crate::common::wrap_packet(&packet, self.network_name.as_str());
            peer.send_packet(packet)
        } else {
            Err(NetworkErr::PeerNotFound)
        }
    }

    fn pow_chain_ref(&self) -> PowChainRef {
        self.pow_chain_ref.clone()
    }

    fn state_chain_ref(&self) -> StateChainRef {
        self.state_chain_ref.clone()
    }

    fn pow_chain_sender(&self) -> &Sender<(SocketAddr, Arc<PowBlock>)> {
        &self.pow_chain_sender
    }

    fn state_chain_sender(&self) -> &Sender<(SocketAddr, Arc<StateBlock>)> {
        &self.state_chain_sender
    }

    fn process_packet(&mut self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        let (is_none_id, conn_type) = {
            let peers = self.peers.read();
            let peer = peers.get(peer).ok_or(NetworkErr::PeerNotFound)?;
            (peer.id.is_none(), peer.connection_type)
        };

        // We should receive a connect packet
        // if the peer's id is non-existent and
        // the connection is of type `Server`.
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

                _ => match ConnectPool::from_bytes(packet) {
                    #[cfg(feature = "miner")]
                    Ok(packet) => {
                        debug!(
                            "Received connect pool packet from {}: {:?}",
                            peer, packet
                        );

                        // Handle connect packet
                        ConnectPool::handle(self, peer, &packet, conn_type)?;

                        Ok(())
                    }

                    #[cfg(not(feature = "miner"))]
                    Ok(_) => {
                        debug!(
                            "Received connect pool packet from {}: {:?}",
                            peer, packet
                        );

                        Err(NetworkErr::NotMiner)
                    }

                    _ => {
                        // Invalid packet, remove peer
                        debug!("Invalid connect packet from {}", peer);
                        Err(NetworkErr::InvalidConnectPacket)
                    }
                } 
            }
        } else {
            crate::common::handle_packet(self, conn_type, peer, &packet)?;

            // Refresh peer timeout timer
            {
                let peers = self.peers.read();
                let peer = peers.get(peer).ok_or(NetworkErr::PeerNotFound)?;
                peer.last_seen.store(0, Ordering::SeqCst);
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

    fn our_node_id(&self) -> &NodeId {
        &self.node_id
    }

    fn peers(&self) -> Arc<RwLock<HashMap<SocketAddr, Peer>>> {
        self.peers.clone()
    }

    fn secret_key(&self) -> &Sk {
        &self.secret_key
    }

    fn bootstrap_cache(&self) -> BootstrapCache {
        self.bootstrap_cache.clone()
    }
}
