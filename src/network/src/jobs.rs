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
            unimplemented!();

            ok(network)
        })
        .map_err(|err| warn!("Validator pool bootstrap checker error: {:?}", err))
        .and_then(|_| Ok(()));

    tokio::spawn(refresh_interval)
}