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
use crate::packet::Packet;
use crate::packets::*;
use crate::peer::{ConnectionType, Peer};
use crate::priority::NetworkPriority;
use crate::validation::sender::Sender as SenderTrait;
use crate::downloader::Downloader;
use chain::*;
use chrono::Duration;
use crypto::NodeId;
use crypto::SecretKey as Sk;
use hashbrown::HashMap;
use mempool::Mempool;
use parking_lot::{Mutex, RwLock};
use persistence::PersistentDb;
use rayon::prelude::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use triomphe::Arc;
use crossbeam_channel::{Receiver, Sender};

/// Peer timeout in milliseconds
const PEER_TIMEOUT: u64 = 1000;
const PING_INTERVAL: u64 = 50;

#[derive(Clone)]
/// Mock network layer used for testing.
pub struct MockNetwork {
    /// Mapping between node ids and their mailboxes
    /// An entry in the mailbox is a tuple of two elements
    /// containing the sender's address and the received packet.
    pub(crate) mailboxes: HashMap<NodeId, Sender<(SocketAddr, Vec<u8>)>>,

    /// Our receiver
    rx: Receiver<(SocketAddr, Vec<u8>)>,

    /// Reference to the `PowChain`
    pow_chain_ref: PowChainRef,

    /// Sender to `PowChain` block buffer
    pow_chain_sender: Sender<(SocketAddr, Arc<PowBlock>)>,

    /// Reference to the `Downloader`
    downloader: Downloader,

    /// Mapping between ips and node ids.
    pub(crate) address_mappings: HashMap<SocketAddr, NodeId>,

    /// Mapping between connected peers and their information
    pub(crate) peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,

    /// Our ip
    ip: SocketAddr,

    /// Our node id
    node_id: NodeId,

    /// Our secret key
    secret_key: Sk,

    /// The port we accept connections on
    port: u16,

    /// The name of the network we are on
    network_name: String,

    /// Associated bootstrap cache
    bootstrap_cache: BootstrapCache,
}

impl NetworkInterface for MockNetwork {
    fn connect(&mut self, address: &SocketAddr) -> Result<(), NetworkErr> {
        info!("Connecting to {:?}", address);

        let mut peer = Peer::new(
            None,
            address.clone(),
            ConnectionType::Client,
            None,
            None,
            None,
            self.bootstrap_cache.clone(),
        );
        let mut connect_packet = Connect::new(self.node_id.clone(), peer.pk.clone());
        connect_packet.sign(&self.secret_key);
        let connect = connect_packet.to_bytes();

        peer.sent_connect = true;

        {
            let mut peers = self.peers.write();
            peers.insert(address.clone(), peer);
        }

        self.send_raw(address, &connect, NetworkPriority::High)
            .unwrap();
        Ok(())
    }

    fn connect_to_known(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn is_connected_to(&self, address: &SocketAddr) -> bool {
        let peers = self.peers.read();
        peers.get(address).is_some()
    }

    fn disconnect(&mut self, peer: &NodeId) -> Result<(), NetworkErr> {
        let mut peers = self.peers.write();
        peers.retain(|_, p| p.id.as_ref() != Some(peer));
        Ok(())
    }

    fn disconnect_from_ip(&mut self, ip: &SocketAddr) -> Result<(), NetworkErr> {
        let mut peers = self.peers.write();
        peers.remove(ip);
        Ok(())
    }

    fn send_to_peer(
        &self,
        peer: &SocketAddr,
        packet: Vec<u8>,
        _priority: NetworkPriority,
    ) -> Result<(), NetworkErr> {
        let id = if let Some(id) = self.address_mappings.get(peer) {
            id
        } else {
            return Err(NetworkErr::PeerNotFound);
        };

        if let Some(mailbox) = self.mailboxes.get(&id) {
            let peers = self.peers.read();
            let peer = peers.get(peer).unwrap();
            let key = peer.rx.as_ref().unwrap();
            let packet = crate::common::wrap_encrypt_packet(
                &packet,
                &self.secret_key,
                key,
                self.network_name.as_str(),
            );
            mailbox.send((self.ip.clone(), packet)).unwrap();
            Ok(())
        } else {
            Err(NetworkErr::PeerNotFound)
        }
    }

    fn send_to_all(&self, packet: &[u8], _priority: NetworkPriority) -> Result<(), NetworkErr> {
        if self.mailboxes.is_empty() {
            return Err(NetworkErr::NoPeers);
        }

        let peers = self.peers();
        let peers = peers.read();
        let ids_to_send_to = peers.iter().map(|(_, peer)| peer.id.as_ref());

        for id in ids_to_send_to {
            if let Some(id) = id {
                let mailbox = self.mailboxes.get(id).unwrap();
                mailbox.send((self.ip.clone(), packet.to_vec())).unwrap();
            }
        }

        Ok(())
    }

    fn send_to_all_except(
        &self,
        exception: &SocketAddr,
        packet: &[u8],
        _priority: NetworkPriority,
    ) -> Result<(), NetworkErr> {
        if self.mailboxes.is_empty() {
            return Err(NetworkErr::NoPeers);
        }

        let peers = self.peers();
        let peers = peers.read();
        let ids_to_send_to = peers
            .iter()
            .filter(|(addr, _)| *addr != exception)
            .map(|(_, peer)| peer.id.as_ref());

        for id in ids_to_send_to {
            if let Some(id) = id {
                let mailbox = self.mailboxes.get(id).unwrap();
                mailbox.send((self.ip.clone(), packet.to_vec())).unwrap();
            }
        }

        Ok(())
    }

    fn pow_chain_ref(&self) -> PowChainRef {
        self.pow_chain_ref.clone()
    }

    fn has_peer(&self, addr: &SocketAddr) -> bool {
        self.peers.read().get(addr).is_some()
    }

    fn has_peer_with_id(&self, id: &NodeId) -> bool {
        unimplemented!()
    }

    fn pow_chain_sender(&self) -> &Sender<(SocketAddr, Arc<PowBlock>)> {
        &self.pow_chain_sender
    }

    fn ban_peer(&self, peer: &NodeId) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn ban_ip(&self, peer: &SocketAddr) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn network_name(&self) -> &str {
        self.network_name.as_str()
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

    fn downloader(&self) -> Downloader {
        self.downloader.clone()
    }

    fn bootstrap_cache(&self) -> BootstrapCache {
        self.bootstrap_cache.clone()
    }

    fn mempool_ref(&self) -> Option<Arc<RwLock<Mempool>>> {
        unimplemented!();
    }

    fn after_connect(&self, _peer: &SocketAddr) {}
}

impl MockNetwork {
    pub fn new(
        node_id: NodeId,
        ip: SocketAddr,
        port: u16,
        network_name: String,
        secret_key: Sk,
        rx: Receiver<(SocketAddr, Vec<u8>)>,
        mailboxes: HashMap<NodeId, Sender<(SocketAddr, Vec<u8>)>>,
        address_mappings: HashMap<SocketAddr, NodeId>,
        pow_chain_sender: Sender<(SocketAddr, Arc<PowBlock>)>,
        pow_chain_ref: PowChainRef,
    ) -> MockNetwork {
        MockNetwork {
            rx,
            mailboxes,
            address_mappings,
            pow_chain_sender,
            pow_chain_ref,
            downloader: Downloader::new(),
            peers: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_cache: BootstrapCache::new(PersistentDb::new_in_memory(), 100000),
            node_id,
            secret_key,
            ip,
            port,
            network_name,
        }
    }

    /// Connects to the peer but neither will send a ping
    /// and pong packets, causing a timeout.
    pub fn connect_no_ping(&mut self, address: &SocketAddr) -> Result<(), NetworkErr> {
        info!("Connecting to {:?}", address);

        let mut peer = Peer::new(
            None,
            address.clone(),
            ConnectionType::Client,
            None,
            None,
            None,
            self.bootstrap_cache.clone(),
        );
        let mut connect_packet = Connect::new(self.node_id.clone(), peer.pk.clone());
        connect_packet.sign(&self.secret_key);
        let connect = connect_packet.to_bytes();

        peer.sent_connect = true;
        peer.send_ping = false;

        {
            let mut peers = self.peers.write();
            peers.insert(address.clone(), peer);
        }

        self.send_raw(address, &connect, NetworkPriority::Low)
            .unwrap();
        Ok(())
    }

    pub fn start_receive_loop(
        network: Arc<Mutex<Self>>,
        pow_block_receiver: Arc<Mutex<Receiver<(SocketAddr, Arc<PowBlock>)>>>,
    ) {
        loop {
            let mut pings: Vec<(SocketAddr, Vec<u8>)> = Vec::new();

            {
                let mut network = network.lock();

                if let Ok((addr, packet)) = network.rx.try_recv() {
                    if let Err(err) = network.process_packet(&addr, &packet) {
                        match err {
                            NetworkErr::InvalidConnectPacket => {
                                network.disconnect_from_ip(&addr).unwrap();
                                network.ban_ip(&addr).unwrap();
                            }
                            err => {
                                debug!("Packet error: {:?}", err);
                                network.disconnect_from_ip(&addr).unwrap();
                                network.ban_ip(&addr).unwrap();
                            }
                        }
                    }
                }

                // Remove peers that have timed out
                {
                    let peers = network.peers();
                    let mut peers = peers.write();
                    peers.retain(|_, p| p.last_seen.load(Ordering::SeqCst) < PEER_TIMEOUT);
                    //network.address_mappings.retain(|addr, _| peers.get(addr).is_some());

                    // Send pings
                    for (addr, p) in peers.iter_mut() {
                        if p.last_ping.load(Ordering::SeqCst) > PING_INTERVAL && p.send_ping {
                            {
                                let mut sender = p.validator.ping_pong.sender.lock();

                                if let Ok(ping) = sender.send(()) {
                                    p.last_ping = Arc::new(AtomicU64::new(0));

                                    debug!("Sending Ping packet to {}", addr);

                                    pings.push((addr.clone(), ping.to_bytes()));
                                };
                            }
                        }
                    }
                }
            }

            let network = network.clone();

            // Dispatch pings
            pings.par_iter().for_each(move |(addr, p)| {
                network
                    .clone()
                    .lock()
                    .send_to_peer(&addr, p.to_vec(), NetworkPriority::Low)
                    .unwrap()
            });
        }
    }
}
