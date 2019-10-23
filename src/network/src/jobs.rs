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

use crate::interface::NetworkInterface;
use crate::network::Network;
use tokio::executor::Spawn;
use tokio::prelude::future::ok;
use tokio::prelude::*;
use tokio_timer::Interval;
use std::time::{Instant, Duration};

#[cfg(feature = "miner")]
const VALIDATOR_BOOTSTRAP_INTERVAL: u64 = 1000;

#[cfg(feature = "miner")]
/// Starts an asynchronous job that checks if the current
/// node can bootstrap to an active validator pool.
pub fn start_validator_bootstrap_check(network: Network) -> Spawn {
    debug!("Starting validator pool bootstrap checker interval...");

    let refresh_interval = Interval::new(Instant::now(), Duration::from_millis(VALIDATOR_BOOTSTRAP_INTERVAL))
        .fold(network, move |mut network, _| {
            debug!("Triggering validator pool bootstrap check...");
            
            let our_node_id = network.our_node_id();

            // Retrieve current state
            let pow_ref = network.pow_chain_ref();
            let pow_state = {
                let chain = pow_ref.chain.read();
                chain.canonical_tip_state()
            };

            // Connect to other validators in the pool if we are also one
            if pow_state.is_pending_or_active(&our_node_id) {
                debug!("Establishing connection to pool peers...");

                let pool_network = if let Some(pool_network) = &network.current_pool {
                    pool_network.clone()
                } else {
                    // TODO: Initialize pool network
                    unimplemented!(); 
                };

                let mut pool_network_clone = pool_network.clone();

                let iter = pow_state.active_validator_lookup
                    .iter()
                    .chain(pow_state.pending_validator_lookup.iter())
                    .filter(move |(_, entry)| !pool_network.is_connected_to(&entry.ip));

                for (id, entry) in iter {
                    pool_network_clone
                        .connect(&entry.ip)
                        .map_err(|err| warn!("Could not connect to pool peer {}! Reason: {:?}", entry.ip, err))
                        .unwrap_or(());
                }
            }

            ok(network)
        })
        .map_err(|err| warn!("Validator pool bootstrap checker error: {:?}", err))
        .and_then(|_| Ok(()));

    tokio::spawn(refresh_interval)
}