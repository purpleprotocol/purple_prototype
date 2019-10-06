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
use chain::{Block, HardChainRef};

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu"))]
use miner::{PurpleMiner, PluginType};

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu"))]
lazy_static! {
    static ref MINER_IS_STARTED: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu"))]
/// Starts the mining process.
pub fn start_miner(pow_chain: HardChainRef) -> Result<(), &'static str> {
    if MINER_IS_STARTED.load(Ordering::Relaxed) {
        return Err("The miner is already started!");
    }

    info!("Starting miner...");
    
    thread::spawn(move || {
        let mut miner = PurpleMiner::new();

        // Flag miner as being started
        MINER_IS_STARTED.store(true, Ordering::Relaxed);

        info!("Miner started!");

        // Check for available headers to mine if the miner is not started.
        //
        // If the miner is started, we check for available solutions.
        loop {
            #[cfg(test)]
            let plugin_type = PluginType::Cuckoo19;

            #[cfg(not(test))]
            let plugin_type = PluginType::Cuckoo30;

            // The miner is started
            if miner.are_solvers_started() {
                if let Some(miner_height) = miner.current_height(plugin_type) {      
                    let tip = pow_chain.canonical_tip();
                    let current_height = tip.height();

                    if miner_height == current_height {
                        // Check for solutions if the height is constant
                        if let Some(solution) = miner.get_solutions() {
                            info!("Found solution for block height {}", miner_height);

                            // TODO: Handle found solution
                            unimplemented!();
                        }
                    } else if miner_height < current_height {
                        let header_hash = tip.block_hash().unwrap();
                        let difficulty = 0; // TODO: Calculate difficulty #118
                        
                        // Re-schedule miner to work on the current height
                        miner.notify(current_height, &header_hash.0, difficulty, plugin_type);
                    } else {
                        unreachable!();
                    }
                } 
            } else {
                // Schedule miner to work on the current tip
                let tip = pow_chain.canonical_tip();
                let current_height = tip.height();
                let header_hash = tip.block_hash().unwrap();
                let difficulty = 0; // TODO: Calculate difficulty #118

                debug!("Starting solvers...");

                // Start solver threads
                miner.start_solvers();

                debug!("Solvers started!");
                
                // Re-schedule miner to work on the current height
                miner.notify(current_height, &header_hash.0, difficulty, plugin_type);
            }

            // Don't hog the scheduler
            thread::sleep_ms(1);
        }
    });
    
    Ok(())
}