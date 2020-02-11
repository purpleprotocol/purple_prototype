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

use crate::network::Network;
use crate::connection::*;
use crate::interface::NetworkInterface;
use persistence::PersistentDb;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use futures::future::FutureExt;
use rand::prelude::IteratorRandom;

pub fn bootstrap(
    network: Network,
    accept_connections: Arc<AtomicBool>,
    db: PersistentDb,
    max_peers: usize,
    bootnodes: Vec<SocketAddr>,
    port: u16,
    start_interval: bool,
) {
    info!("Bootstrapping...");

    // Try to first connect to the nodes in the bootstrap cache.
    if !network.bootstrap_cache.is_empty() {
        let fut = async move {
            let mut network = network.clone();

            let peers_to_connect: Vec<SocketAddr> = network.bootstrap_cache
                .entries()
                .map(|e| e.to_socket_addr(port))
                .choose_multiple(&mut rand::thread_rng(), max_peers as usize);

            let network_clone = network.clone();
            let network_clone2 = network.clone();
            let accept_connections = accept_connections.clone();
            let accept_connections_clone = accept_connections.clone();
            let bootnodes_clone = bootnodes.clone();

            let mut futures = vec![];

            for addr in peers_to_connect.iter() {
                futures.push(try_connect_to_peer(network.clone(), addr).boxed());
            }

            // Try to connect to all previously encountered peers
            futures::future::join_all(futures).await;

            // Connect to bootstrap nodes if we haven't
            // yet reached the maximum amount of peers.
            if network_clone.peer_count() < max_peers {
                let network = network_clone.clone();
                let mut futures = vec![];

                for addr in bootnodes.iter() {
                    futures.push(try_connect_to_peer(network.clone(), addr).boxed());
                }

                // Try to connect to bootnodes
                futures::future::join_all(futures).await;

                info!("Finished bootstrap");
            } else {
                info!("Finished bootstrap");
            }

            if start_interval {
                start_peer_list_refresh_interval(network_clone, accept_connections_clone, db.clone(), max_peers, bootnodes_clone, port);
            }
        };

        tokio::spawn(fut);
    } else {
        debug!("Bootstrap cache is empty! Connecting to bootnodes...");

        let mut peers_to_connect: Vec<SocketAddr> = Vec::with_capacity(bootnodes.len());

        for addr in bootnodes.iter().take(max_peers) {
            peers_to_connect.push(*addr);
        }

        let accept_connections = accept_connections.clone();
        let accept_connections_clone = accept_connections.clone();
        let network = network.clone();
        let network_clone = network.clone();

        let fut = async move {
            let mut futures = vec![];

            for addr in peers_to_connect.iter() {
                futures.push(try_connect_to_peer(network.clone(), addr).boxed());
            }

            // Try to connect to all previously encountered peers
            futures::future::join_all(futures).await;

            if start_interval {
                start_peer_list_refresh_interval(network_clone, accept_connections_clone, db.clone(), max_peers, bootnodes, port);
            }
        };

        tokio::spawn(fut);
    }
}

async fn try_connect_to_peer(mut network: Network, addr: &SocketAddr) {
    network
        .connect(&addr)
        .map_err(|err| warn!("Could not connect to {:?}: {:?}", addr, err))
        .unwrap_or(());
}

pub mod cache;
pub mod entry;
pub use self::cache::*;