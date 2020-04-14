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
use crate::interface::NetworkInterface;
use crate::packets::{RequestPeers, SendPeers};
use crate::protocol_flow::request_peers::receiver_state::RequestPeersReceiverState;
use crate::validation::receiver::Receiver;
use hashbrown::HashSet;
use rand::prelude::IteratorRandom;
use std::net::SocketAddr;

#[derive(Debug)]
pub struct RequestPeersReceiver {
    state: RequestPeersReceiverState,
    bootstrap_cache: BootstrapCache,
}

impl RequestPeersReceiver {
    pub fn new(bootstrap_cache: BootstrapCache) -> RequestPeersReceiver {
        RequestPeersReceiver {
            state: RequestPeersReceiverState::default(),
            bootstrap_cache,
        }
    }
}

impl Receiver<RequestPeers, SendPeers> for RequestPeersReceiver {
    /// Attempts to receive a packet and outputs a new packet
    /// to be sent back if the receiver is able to receive a
    /// packet.
    fn receive<N: NetworkInterface>(
        &mut self,
        network: &N,
        sender: &SocketAddr,
        packet: &RequestPeers,
    ) -> Result<SendPeers, NetworkErr> {
        if let RequestPeersReceiverState::Ready = self.state {
            // First attempt to send the peers we are connected to
            let connected_peers: Vec<SocketAddr> = {
                let peers = network.peers();

                peers
                    .iter()
                    // Filter out the requester
                    .filter(|v| v.key() != sender)
                    .map(|v| v.ip.clone())
                    .choose_multiple(&mut rand::thread_rng(), packet.requested_peers as usize)
            };

            if connected_peers.len() == packet.requested_peers as usize {
                Ok(SendPeers::new(connected_peers, packet.nonce))
            } else {
                let connected_set: HashSet<&SocketAddr> = connected_peers.iter().collect();
                let mut peers = self
                    .bootstrap_cache
                    .entries()
                    .map(|e| e.to_socket_addr(network.port()))
                    .filter(|addr| !connected_set.contains(addr) && addr != sender)
                    .choose_multiple(
                        &mut rand::thread_rng(),
                        (packet.requested_peers as usize) - connected_peers.len(),
                    );

                peers.extend_from_slice(&connected_peers);
                Ok(SendPeers::new(peers, packet.nonce))
            }
        } else {
            unreachable!();
        }
    }

    fn done(&self) -> bool {
        unimplemented!();
    }

    /// Returns true if the receiver is able to receive packets.
    fn can_receive(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        unimplemented!();
    }
}
