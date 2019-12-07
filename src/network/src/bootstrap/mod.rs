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

use crate::network::Network;
use crate::connection::*;
use crate::interface::NetworkInterface;
use futures::stream;
use futures::Future;
use futures::Stream;
use persistence::PersistentDb;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::executor::Spawn;
use rand::prelude::IteratorRandom;

pub fn bootstrap(
    network: Network,
    accept_connections: Arc<AtomicBool>,
    db: PersistentDb,
    max_peers: usize,
    bootnodes: Vec<SocketAddr>,
    port: u16,
    start_interval: bool,
) -> Spawn {
    info!("Bootstrapping...");

    // Try to first connect to the nodes in the bootstrap cache.
    if !network.bootstrap_cache.is_empty() {
        let peers_to_connect: Vec<SocketAddr> = network.bootstrap_cache
            .entries()
            .map(|e| e.to_socket_addr(port))
            .choose_multiple(&mut rand::thread_rng(), max_peers as usize);

        let mut network = network.clone();
        let network_clone = network.clone();
        let network_clone2 = network.clone();
        let network_clone3 = network.clone();
        let accept_connections = accept_connections.clone();
        let accept_connections_clone = accept_connections.clone();
        let accept_connections_clone2 = accept_connections.clone();
        let bootnodes_clone = bootnodes.clone();

        let fut = stream::iter_ok(peers_to_connect)
            .for_each(move |addr| {
                Ok(network.connect(&addr).unwrap_or(()))
            })
            .and_then(move |_| {
                // Connect to bootstrap nodes if we haven't
                // yet reached the maximum amount of peers.
                if network_clone.peer_count() < max_peers {
                    let mut network = network_clone.clone();

                    let fut = stream::iter_ok(bootnodes).for_each(move |addr| {
                        Ok(network.connect(&addr).unwrap_or(()))
                    });

                    tokio::spawn(fut);
                    info!("Finished bootstrap");
                    Ok(())
                } else {
                    info!("Finished bootstrap");
                    Ok(())
                }
            });

        tokio::spawn(fut.and_then(move |_| {
            if start_interval {
                start_peer_list_refresh_interval(network_clone3, accept_connections_clone2, db.clone(), max_peers, bootnodes_clone, port);
            }

            Ok(())
        }))
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

        let fut = stream::iter_ok(peers_to_connect).for_each(move |addr| {
            connect_to_peer(network.clone(), accept_connections.clone(), &addr)
        });

        tokio::spawn(fut.and_then(move |_| {
            if start_interval {
                start_peer_list_refresh_interval(network_clone, accept_connections_clone, db.clone(), max_peers, bootnodes, port);
            }

            Ok(())
        }))
    }
}

pub mod cache;
pub mod entry;
pub use self::cache::*;