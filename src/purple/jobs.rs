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

#![allow(deprecated, unused)]

use account::NormalAddress;
use chain::{Block, CheckpointBlock, PowBlock, PowChainRef};
use network::{Network, NetworkInterface};
use network::{NetworkPriority, Packet};
use parking_lot::RwLock;
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use triomphe::Arc;
use std::thread;

#[cfg(any(
    feature = "miner-cpu",
    feature = "miner-gpu",
    feature = "miner-cpu-avx",
    feature = "miner-test-mode"
))]
use miner::{PluginType, Proof, PurpleMiner};

#[cfg(any(
    feature = "miner-cpu",
    feature = "miner-gpu",
    feature = "miner-cpu-avx",
    feature = "miner-test-mode"
))]
lazy_static! {
    static ref MINER_IS_STARTED: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref MINER_IS_PAUSED: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

#[cfg(any(
    feature = "miner-cpu",
    feature = "miner-gpu",
    feature = "miner-cpu-avx",
    feature = "miner-test-mode"
))]
pub fn is_miner_paused() -> bool {
    MINER_IS_PAUSED.load(Ordering::Relaxed)
}

#[cfg(any(
    feature = "miner-cpu",
    feature = "miner-gpu",
    feature = "miner-cpu-avx",
    feature = "miner-test-mode"
))]
pub fn unpause_miner() -> bool {
    let previous = MINER_IS_PAUSED.load(Ordering::Relaxed);
    MINER_IS_PAUSED.store(false, Ordering::Relaxed);
    previous
}

#[cfg(any(
    feature = "miner-cpu",
    feature = "miner-gpu",
    feature = "miner-cpu-avx",
    feature = "miner-test-mode"
))]
/// Starts the mining process.
pub fn start_miner(
    pow_chain: PowChainRef,
    network: Network,
    ip: SocketAddr,
    proof_delay: Option<u32>,
    collector_address: NormalAddress
) -> Result<(), &'static str> {
    if MINER_IS_STARTED.load(Ordering::Relaxed) {
        return Err("The miner is already started!");
    }

    info!("Starting miner...");

    let builder = thread::Builder::new().name("Miner main thread".to_owned());

    builder.spawn(move || {
        let miner = PurpleMiner::new();
        let miner = Rc::new(RefCell::new(miner));

        // Flag miner as being started
        MINER_IS_STARTED.store(true, Ordering::Relaxed);

        info!("Miner started!");

        // Check for available headers to mine if the miner is not started.
        //
        // If the miner is started, we check for available solutions.
        loop {
            #[cfg(feature = "miner-test-mode")]
            let plugin_type = PluginType::Cuckoo0;

            #[cfg(not(feature = "miner-test-mode"))]
            let plugin_type = PluginType::Cuckoo29;

            let are_solvers_started = { miner.borrow().are_solvers_started() };

            // The miner is started
            if are_solvers_started {
                let current_height = { miner.borrow().current_height(plugin_type) };

                if let Some(miner_height) = current_height { 
                    let tip = pow_chain.canonical_tip();
                    let tip_state = pow_chain.canonical_tip_state();
                    let current_height = tip.height();

                    if miner_height == current_height {
                        let solutions = { miner.borrow().get_solutions() };

                        // Check for solutions if the height is constant
                        if let Some(solutions) = solutions {
                            #[cfg(feature = "miner-test-mode")]     
                            {
                                // Sleep for delay time
                                if let Some(proof_delay) = proof_delay {
                                    thread::sleep_ms(proof_delay);
                                }
                            }

                            info!("Found solution for block height {}", miner_height);
                            let solution = solutions.sols[0];
                            let nonce = solution.nonce() as u32;
                            let sol_u64s = solution.to_u64s();
                            let proof = Proof::new(sol_u64s, nonce, solutions.edge_bits as u8);

                            let node_id = network.our_node_id().clone();

                            // Create block
                            let mut block = CheckpointBlock::new(
                                tip_state.last_checkpoint.clone(), 
                                collector_address,
                                ip,
                                miner_height + 1,
                                proof,
                                node_id,
                            );
                            block.sign_miner(network.secret_key());
                            block.compute_hash();
                            let block = Arc::new(block);
                            let block = PowBlock::Checkpoint(block);
                            let block = Arc::new(block);

                            // Append block to our chain
                            let result = pow_chain.append_block(block.clone()).map_err(|err| warn!("Could not append block to pow chain! Reason: {:?}", err));

                            // Only propagate block if the chain append was successful
                            if let Ok(_) = result {
                                debug!("Creating block...");

                                let packet = ForwardBlock::new(block);
                                let packet = packet.to_bytes();

                                debug!("Pausing solvers...");

                                // Pause solvers
                                { (*miner).borrow_mut().pause_solvers(); }
                                MINER_IS_PAUSED.store(true, Ordering::Relaxed);

                                debug!("Sending block...");

                                // Send block to all of our peers
                                network.send_to_all(&packet, NetworkPriority::Medium).map_err(|err| warn!("Could not send pow block! Reason: {:?}", err));

                                // Wait a bit for buffers to flush
                                thread::sleep_ms(150);
                            } else {
                                warn!("Could not send pow block! Reason: Unsuccessful chain append");
                            }
                        } else {
                            //debug!("No solution found...");
                            // TODO: Maybe hook this to a progress visualizer
                        }
                    } else if miner_height < current_height {
                        try_notify(miner.clone(), pow_chain.clone(), plugin_type);
                    } else {
                        unreachable!();
                    }
                } else {
                    // TODO: Maybe hook this to a visualizer
                    //debug!("Miner is stand-by...");
                }
            } else {
                try_notify(miner.clone(), pow_chain.clone(), plugin_type);
            }

            // Don't hog the scheduler
            thread::sleep_ms(1);
        }
    }).map_err(|_| "Could not start miner thread!")?;

    Ok(())
}

#[cfg(any(
    feature = "miner-cpu",
    feature = "miner-gpu",
    feature = "miner-cpu-avx",
    feature = "miner-test-mode"
))]
fn try_notify(
    mut miner: Rc<RefCell<PurpleMiner>>,
    pow_chain: PowChainRef,
    plugin_type: PluginType,
) {
    let is_paused = MINER_IS_PAUSED.load(Ordering::Relaxed);

    if !is_paused {
        let mut miner = (*miner).borrow_mut();

        // Schedule miner to work on the current tip
        let tip_state = pow_chain.canonical_tip_state();
        let tip = pow_chain.canonical_tip();
        let current_height = tip.height();
        let header_hash = tip.block_hash().unwrap();
        let difficulty = tip_state.difficulty;

        if !miner.are_solvers_started() {
            debug!("Starting solvers...");

            // Start solver threads
            miner.start_solvers();

            debug!("Solvers started!");
        }

        miner.notify(current_height, &header_hash.0, difficulty, plugin_type);
    } else {
        debug!("Miner is paused...");
        thread::sleep_ms(1000);
    }
}
