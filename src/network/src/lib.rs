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

#![allow(irrefutable_let_patterns, unused)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate log;
#[macro_use]
extern crate bin_tools;

#[cfg(test)]
pub mod mock;

pub mod bootstrap;
pub mod packets;
pub mod jobs;
mod common;
mod connection;
mod error;
mod handlers;
mod header;
mod interface;
mod network;
mod packet;
mod peer;
mod protocol_flow;
mod validation;
mod priority;

pub use crate::bootstrap::*;
pub use crate::connection::*;
pub use crate::error::*;
pub use crate::handlers::*;
pub use crate::interface::*;
pub use crate::network::*;
pub use crate::packet::*;
pub use crate::peer::*;
pub use crate::priority::*;

#[cfg(test)]
use tempdir::TempDir;

#[cfg(test)]
use std::thread;

#[cfg(test)]
use crypto::NodeId;

#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
use crossbeam_channel::*;

#[cfg(test)]
use parking_lot::{Mutex, RwLock};

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
/// Test helper for initializing mock networks. Also initializes
/// listener threads.
pub fn init_test_networks(peers: usize) -> Vec<(Arc<Mutex<MockNetwork>>, SocketAddr, NodeId)> {
    let mut mailboxes = HashMap::new();
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
    let mut networks: Vec<(Arc<Mutex<MockNetwork>>, SocketAddr, NodeId)> =
        Vec::with_capacity(peers);

    for i in 0..peers {
        let (rx, tx) = unbounded();
        let (rx1, tx1) = unbounded();
        address_mappings.insert(addresses[i].clone(), identities[i].0.clone());
        mailboxes.insert(identities[i].0.clone(), rx);
        let mb_clone = mailboxes.clone();
        let ids_clone = identities.clone();
        let am_clone = address_mappings.clone();
        let a_clone = addresses.clone();
        let (s, r) = unbounded();

        thread::Builder::new()
            .name(format!("Peer {}", i + 1))
            .spawn(move || {
                let mailboxes = mb_clone;
                let identities = ids_clone;
                let address_mappings = am_clone;
                let addresses = a_clone;
                let temp_dir = TempDir::new("storage").unwrap();

                let (db1, db2) = (
                    test_helpers::init_tempdb(),
                    test_helpers::init_tempdb(),
                );

                let pow_chain = chain::init(db1, db2, true);

                let network = MockNetwork::new(
                    identities[i].0.clone(),
                    addresses[i].clone(),
                    44034,
                    "test_network".to_owned(),
                    identities[i].1.clone(),
                    tx,
                    mailboxes.clone(),
                    address_mappings.clone(),
                    rx1,
                    pow_chain,
                );

                let network = Arc::new(Mutex::new(network));
                s.send(network.clone()).unwrap();

                MockNetwork::start_receive_loop(
                    network,
                    Arc::new(Mutex::new(tx1)),
                )
            })
            .unwrap();

        // Wait for thread to build and send us the network object
        let network = r.recv().unwrap();

        networks.push((network, addresses[i].clone(), identities[i].0.clone()));
    }

    for i in 0..peers {
        let mut network = networks[i].0.lock();
        network.mailboxes = mailboxes.clone();
        network.address_mappings = address_mappings.clone();
    }

    networks
}
