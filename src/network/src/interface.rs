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

use crate::bootstrap::cache::BootstrapCache;
use crate::error::NetworkErr;
use crate::peer::Peer;
use crate::priority::NetworkPriority;
use crate::downloader::Downloader;
use chain::*;
use crypto::{NodeId, SecretKey as Sk};
use hashbrown::HashMap;
use mempool::Mempool;
use parking_lot::RwLock;
use std::net::SocketAddr;
use triomphe::Arc;

#[cfg(not(test))]
use tokio::sync::mpsc::Sender;

#[cfg(test)]
use crossbeam_channel::Sender;

/// Generic network layer interface.
pub trait NetworkInterface: Clone + Send {
    /// Attempts to connect to the peer with the given ip.
    fn connect(&mut self, address: &SocketAddr) -> Result<(), NetworkErr>;

    /// Attempts to connect to a previously encountered peer
    fn connect_to_known(&self, peer: &NodeId) -> Result<(), NetworkErr>;

    /// Returns true if the network has the given address in its peer list.
    fn is_connected_to(&self, address: &SocketAddr) -> bool;

    /// Disconnects from the peer with the given `NodeId`.
    fn disconnect(&mut self, peer: &NodeId) -> Result<(), NetworkErr>;

    /// Disconnects from the peer with the given ip address.
    fn disconnect_from_ip(&mut self, ip: &SocketAddr) -> Result<(), NetworkErr>;

    /// Sends a packet to a specific peer.
    fn send_to_peer(
        &self,
        peer: &SocketAddr,
        packet: Vec<u8>,
        priority: NetworkPriority,
    ) -> Result<(), NetworkErr>;

    /// Sends a packet to all peers.
    fn send_to_all(&self, packet: &[u8], priority: NetworkPriority) -> Result<(), NetworkErr>;

    /// Sends a packet to all peers except the given address.
    fn send_to_all_except(
        &self,
        exception: &SocketAddr,
        packet: &[u8],
        priority: NetworkPriority,
    ) -> Result<(), NetworkErr>;

    /// Sends a raw packet to a specific peer. This
    /// means that the packet will be un-encrypted.
    fn send_raw(
        &self,
        peer: &SocketAddr,
        packet: &[u8],
        priority: NetworkPriority,
    ) -> Result<(), NetworkErr>;

    /// Callback that processes each packet that is received from any peer.
    fn process_packet(&mut self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr>;

    /// Returns true if the peer with the given `SocketAddr` exists
    /// in the peer table.
    fn has_peer(&self, addr: &SocketAddr) -> bool;

    /// Returns true if the peer with the given `NodeId` exists
    /// in the peer table.
    fn has_peer_with_id(&self, id: &NodeId) -> bool;

    /// Bans the peer with the node id
    fn ban_peer(&self, peer: &NodeId) -> Result<(), NetworkErr>;

    /// Bans any further connections from the given ip.
    fn ban_ip(&self, peer: &SocketAddr) -> Result<(), NetworkErr>;

    /// Returns a reference to our node id.
    fn our_node_id(&self) -> &NodeId;

    /// Returns the external port we are accepting connections on.
    fn port(&self) -> u16;

    /// Returns a reference to the peer table `RwLock`.
    fn peers(&self) -> Arc<RwLock<HashMap<SocketAddr, Peer>>>;

    /// Returns a reference to the `PowChain`.
    fn pow_chain_ref(&self) -> PowChainRef;

    /// Returns a reference to the `Downloader`
    fn downloader(&self) -> Downloader;

    /// Returns a reference to a `PowChain` mpsc sender.
    /// Use this to buffer blocks that are to be appended
    /// to the chain.
    fn pow_chain_sender(&self) -> &Sender<(SocketAddr, Arc<PowBlock>)>;

    /// Returns a reference to the signing secret key
    fn secret_key(&self) -> &Sk;

    /// Returns a handle to the bootstrap cache.
    fn bootstrap_cache(&self) -> BootstrapCache;

    /// Returns a reference to the mempool if we have one.
    fn mempool_ref(&self) -> Option<Arc<RwLock<Mempool>>>;

    /// Call-back that executes after a `Connect` or `ConnectPool`
    /// packet has been successfully processed from a peer.
    fn after_connect(&self, peer: &SocketAddr);
}
