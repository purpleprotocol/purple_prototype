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

#![allow(unused)]

use crate::interface::NetworkInterface;
use crate::network::Network;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Starts jobs that are executed once every ~1 second.
pub async fn start_periodic_jobs(network: Network) {
    loop {
        debug!("Executing periodic jobs...");
        tokio::spawn(account_bytes_read_write_for_peers(network.clone()));
        tokio::time::delay_for(Duration::from_secs(1)).await;
    }
}

/// Traverses each peer and sets the amount of bytes read and wrote
/// for the last second
async fn account_bytes_read_write_for_peers(network: Network) {
    let peers = network.peers();

    for peer in peers.iter() {
        let bytes_read = peer.bytes_read.clone();
        let past_bytes_read = peer.past_bytes_read.clone();
        let bytes_write = peer.bytes_write.clone();
        let past_bytes_write = peer.past_bytes_write.clone();

        tokio::spawn(async move {
            // Set past bytes read as the current accumulated value
            let bytes_read = bytes_read.swap(0, Ordering::SeqCst);
            past_bytes_read.store(bytes_read, Ordering::SeqCst);

            // Set past bytes write as the current accumulated value
            let bytes_write = bytes_write.swap(0, Ordering::SeqCst);
            past_bytes_write.store(bytes_write, Ordering::SeqCst);
        });
    }
}
