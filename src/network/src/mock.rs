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
use std::sync::Arc;
use std::collections::VecDeque;
use hashbrown::HashMap;
use parking_lot::Mutex;
use NodeId;
use Peer;

#[derive(Debug, Clone)]
pub struct MockNetwork {
    /// Mapping between node ids and their mailboxes
    mailboxes: Arc<Mutex<HashMap<NodeId, VecDeque<Vec<u8>>>>>,

    /// Mapping between connected peers and their information
    peers: HashMap<NodeId, Peer>,

    /// Our node id
    node_id: NodeId,

    /// The name of the network we are on
    network_name: String
}

impl NetworkInterface for MockNetwork {
    fn send_to_peer(&self, peer: &NodeId, packet: &[u8]) -> Result<(), NetworkErr> {
        let mut mailboxes = self.mailboxes.lock();

        if let Some(mailbox) = mailboxes.get_mut(peer) {
            mailbox.push_front(packet.to_vec());
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
            mailbox.push_front(packet.to_vec());
        }

        Ok(())
    }

    fn process_packet(&self, peer: &NodeId, packet: &[u8]) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

impl MockNetwork {
    pub fn new(node_id: NodeId, network_name: String, mailboxes: Arc<Mutex<HashMap<NodeId, VecDeque<Vec<u8>>>>>) -> MockNetwork {
        MockNetwork {
            mailboxes,
            peers: HashMap::new(),
            node_id,
            network_name
        }
    }
}
