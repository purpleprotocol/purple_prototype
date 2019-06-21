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

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate log;

extern crate chain;
extern crate byteorder;
extern crate crypto;
extern crate env_logger;
extern crate futures;
extern crate hashbrown;
extern crate hashdb;
extern crate hex;
extern crate parking_lot;
extern crate persistence;
extern crate rand;
extern crate rlp;
extern crate tokio;
extern crate tokio_io_timeout;
extern crate tokio_timer;
extern crate chrono;

#[cfg(test)]
pub mod mock;

mod bootstrap;
mod connection;
mod error;
mod interface;
mod network;
pub mod packets;
mod peer;
mod packet;
mod common;
mod handlers;

pub use packet::*;
pub use bootstrap::*;
pub use connection::*;
pub use error::*;
pub use interface::*;
pub use network::*;
pub use peer::*;
pub use handlers::*;

#[cfg(test)]
use crypto::NodeId;

#[cfg(test)]
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

#[cfg(test)]
use rand::prelude::*;

#[cfg(test)]
pub fn random_socket_addr() -> SocketAddr {
    let mut thread_rng = rand::thread_rng();
    let i1 = thread_rng.gen();
    let i2 = thread_rng.gen();
    let i3 = thread_rng.gen();
    let i4 = thread_rng.gen();

    let addr = IpAddr::V4(Ipv4Addr::new(i1, i2, i3, i4));
    SocketAddr::new(addr, 44034)
}

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use std::sync::mpsc::*;

#[cfg(test)]
use parking_lot::{RwLock, Mutex};

#[cfg(test)]
use hashbrown::HashMap;

#[cfg(test)]
use persistence::PersistentDb;

#[cfg(test)]
use chain::*;

#[cfg(test)]
use crate::mock::MockNetwork;

#[cfg(test)]
use crypto::SecretKey;

#[cfg(test)]
/// Test helper for initializing mock networks
pub fn init_test_networks(peers: usize) -> Vec<(Arc<Mutex<MockNetwork>>, SocketAddr, NodeId, Arc<Mutex<Receiver<(SocketAddr, Arc<EasyBlock>)>>>, Arc<Mutex<Receiver<(SocketAddr, Arc<HardBlock>)>>>, Arc<Mutex<Receiver<(SocketAddr, Arc<StateBlock>)>>>)> {
    let mut mailboxes = HashMap::new();
    let chains: Vec<(EasyChainRef, HardChainRef, StateChainRef)> = (0..peers)
        .into_iter()
        .map(|_| (test_helpers::init_tempdb(), test_helpers::init_tempdb(), test_helpers::init_tempdb(), test_helpers::init_tempdb()))
        .map(|(db1, db2, db3, db4)| (Arc::new(RwLock::new(EasyChain::new(db1, ()))), Arc::new(RwLock::new(HardChain::new(db2, ()))), Arc::new(RwLock::new(StateChain::new(db3, db4)))))
        .map(|(easy, hard, state)| (EasyChainRef::new(easy), HardChainRef::new(hard), StateChainRef::new(state)))
        .collect();

    let addresses: Vec<SocketAddr> = (0..peers)
        .into_iter()
        .map(|_| crate::random_socket_addr())
        .collect();

    let identities: Vec<(NodeId, SecretKey)> = (0..peers)
        .into_iter()
        .map(|_| crypto::gen_keypair())
        .map(|(pk, sk)| (NodeId::from_pkey(pk), sk))
        .collect();

    let mut address_mappings = HashMap::new();
    let mut networks: Vec<(Arc<Mutex<MockNetwork>>, SocketAddr, NodeId, Arc<Mutex<Receiver<(SocketAddr, Arc<EasyBlock>)>>>, Arc<Mutex<Receiver<(SocketAddr, Arc<HardBlock>)>>>, Arc<Mutex<Receiver<(SocketAddr, Arc<StateBlock>)>>>)> = Vec::with_capacity(peers);

    for i in 0..peers {
        let (rx, tx) = channel();
        let (rx1, tx1) = channel();
        let (rx2, tx2) = channel();
        let (rx3, tx3) = channel();
        address_mappings.insert(addresses[i].clone(), identities[i].0.clone());
        mailboxes.insert(identities[i].0.clone(), rx);
        let network = MockNetwork::new(
            identities[i].0.clone(), 
            addresses[i].clone(), 
            "test_network".to_owned(), 
            identities[i].1.clone(), 
            tx, 
            mailboxes.clone(), 
            address_mappings.clone(),
            rx1,
            rx2,
            rx3,
            chains[i].0.clone(),
            chains[i].1.clone(),
            chains[i].2.clone(),
        );

        let network = Arc::new(Mutex::new(network));
        networks.push((network, addresses[i].clone(), identities[i].0.clone(), Arc::new(Mutex::new(tx1)), Arc::new(Mutex::new(tx2)), Arc::new(Mutex::new(tx3))));
    }

    for i in 0..peers {
        let mut network = networks[i].0.lock();
        network.mailboxes = mailboxes.clone();
        network.address_mappings = address_mappings.clone();
    }

    networks
}