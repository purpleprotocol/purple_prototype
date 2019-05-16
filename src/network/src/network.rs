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
use std::net::SocketAddr;
use crypto::SecretKey as Sk;
use hashbrown::{HashSet, HashMap};
use std::sync::Arc;
use parking_lot::Mutex;
use NodeId;
use Peer;

#[derive(Debug, Clone)]
pub struct Network {
    /// Mapping between connected ips and peer information
    peers: HashMap<SocketAddr, Arc<Mutex<Peer>>>,

    /// Our node id
    pub(crate) node_id: NodeId,

    /// Our secret key
    pub(crate) secret_key: Sk,

    /// The name of the network we are on
    network_name: String,

    /// Maximum number of allowed peers, default is 8
    pub(crate) max_peers: usize,
}

impl Network {
    pub fn new(node_id: NodeId, network_name: String, secret_key: Sk, max_peers: usize) -> Network {
        Network {
            peers: HashMap::with_capacity(max_peers),
            node_id,
            network_name,
            secret_key,
            max_peers
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr, peer: Arc<Mutex<Peer>>) -> Result<(), NetworkErr> {
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
            Some(peer) => peer.lock().set_id(node_id),
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
            Some(peer) => peer.lock().id.is_none(),
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

    fn disconnect(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn disconnect_from_ip(&self, ip: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_peer(&self, peer: &NodeId, packet: &[u8]) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn send_to_all(&self, packet: &[u8]) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn process_packet(&mut self, peer: &SocketAddr, packet: &[u8]) -> Result<(), NetworkErr> {
        // We should receive a connect packet
        // if the peer's id is non-existent.
        if self.is_none_id(peer) {
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
