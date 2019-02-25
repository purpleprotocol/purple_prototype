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

use std::net::SocketAddr;
use NodeId;
use Peer;

#[derive(Debug, Clone)]
pub struct Network {
    /// List of peers we are connected to
    peers: Vec<Peer>,

    /// Our node id
    node_id: NodeId,

    /// The name of the network we are on
    network_name: String,
}

impl Network {
    pub fn new(node_id: NodeId, network_name: String) -> Network {
        Network {
            peers: Vec::new(),
            node_id: node_id,
            network_name: network_name,
        }
    }

    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.push(peer);
    }

    /// Returns the number of listed peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Sets the node id of the peer with the given address.
    ///
    /// This function will panic if there is no entry for the given address.
    pub fn set_node_id(&mut self, addr: &SocketAddr, node_id: NodeId) {
        match self.peers.iter().position(|x| x.ip == *addr) {
            Some(idx) => self.peers[idx].set_id(node_id),
            None => panic!("There is no listed peer with the given address!"),
        };
    }

    /// Removes the peer entry with the given address.
    ///
    /// This function will panic if there is no entry for the given address.
    pub fn remove_peer_with_addr(&mut self, addr: &SocketAddr) {
        match self.peers.iter().position(|x| x.ip == *addr) {
            Some(idx) => self.peers.remove(idx),
            None => panic!("There is no listed peer with the given address!"),
        };
    }

    /// Returns true if the peer with the given address has a `None` id field.
    ///
    /// This function will panic if there is no entry for the given address.
    pub fn is_none_id(&self, addr: &SocketAddr) -> bool {
        match self.peers.iter().position(|x| x.ip == *addr) {
            Some(idx) => self.peers[idx].id.is_none(),
            None => panic!("There is no listed peer with the given address!"),
        }
    }
}
