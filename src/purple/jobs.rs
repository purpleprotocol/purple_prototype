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

use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicBool};
use std::thread;
use parking_lot::RwLock;

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu"))]
use miner::PurpleMiner;

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu"))]
lazy_static! {
    static ref MINER_IS_STARTED: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu"))]
/// Starts the mining process.
pub fn start_miner() -> Result<(), &'static str> {
    if MINER_IS_STARTED.load(Ordering::Relaxed) {
        return Err("The miner is already started!");
    }

    info!("Starting miner...");
    
    thread::spawn(move || {
        let miner = PurpleMiner::new();

        // Flag miner as being started
        MINER_IS_STARTED.store(true, Ordering::Relaxed);

        info!("Miner started!");

        // Check for available headers to mine if the miner is not started.
        //
        // If the miner is started, we check for available solutions.
        loop {
            //

            // Don't hog the scheduler
            thread::yield_now();
        }
    });
    
    Ok(())
}