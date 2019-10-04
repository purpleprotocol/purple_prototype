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

use crate::packet::Packet;
use crate::packets::ForwardBlock;
use crate::{Network, NetworkInterface};
use chain::*;
use futures::future::ok;
use futures::prelude::*;
use futures::sync::mpsc::Receiver;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;

/// Time in milliseconds to poll chains for buffered switch requests.
const SWITCH_POLL_INTERVAL: u64 = 1;

/// Starts a loop for each chain that will attempt
/// to perform buffered chain switches.
pub fn start_chains_switch_poll(hard_chain: HardChainRef, state_chain: StateChainRef) {
    let hard_interval_fut =
        Interval::new(Instant::now(), Duration::from_millis(SWITCH_POLL_INTERVAL))
            .fold(hard_chain, |hard_chain, _| {
                let has_switch_requests = {
                    let chain = hard_chain.chain.read();
                    chain.has_switch_requests()
                };

                // Flush buffer only if the chain has switch requests
                //
                // TODO: Rate limit this
                if has_switch_requests {
                    let mut chain = hard_chain.chain.write();
                    chain.flush_switch_buffer();
                }

                ok(hard_chain)
            })
            .map_err(|e| warn!("Hard switch poll err: {:?}", e))
            .and_then(|_| ok(()));

    let state_interval_fut =
        Interval::new(Instant::now(), Duration::from_millis(SWITCH_POLL_INTERVAL))
            .fold(state_chain, |state_chain, _| {
                let has_switch_requests = {
                    let chain = state_chain.chain.read();
                    chain.has_switch_requests()
                };

                // Flush buffer only if the chain has switch requests
                //
                // TODO: Rate limit this
                if has_switch_requests {
                    let mut chain = state_chain.chain.write();
                    chain.flush_switch_buffer();
                }

                ok(state_chain)
            })
            .map_err(|e| warn!("State switch poll err: {:?}", e))
            .and_then(|_| ok(()));

    tokio::spawn(hard_interval_fut);
    tokio::spawn(state_interval_fut);
}

/// Listens for blocks on chain receivers and
/// forwards them to their respective chains.
pub fn start_block_listeners(
    network: Network,
    hard_chain: HardChainRef,
    state_chain: StateChainRef,
    hard_receiver: Receiver<(SocketAddr, Arc<HardBlock>)>,
    state_receiver: Receiver<(SocketAddr, Arc<StateBlock>)>,
) {
    let loop_fut_hard = hard_receiver
        .fold(
            (network.clone(), hard_chain),
            |(network, hard_chain), (addr, block)| {
                debug!("Received HardBlock {:?}", block.block_hash().unwrap());
                let chain_result = {
                    let mut chain = hard_chain.chain.write();
                    chain.append_block(block.clone())
                };

                match chain_result {
                    Ok(()) => {
                        // Forward block
                        let packet =
                            ForwardBlock::new(Arc::new(BlockWrapper::HardBlock(block)));
                        network
                            .send_to_all_except(&addr, &packet.to_bytes())
                            .unwrap();
                    }
                    Err(err) => info!(
                        "Chain Error for block {:?}: {:?}",
                        block.block_hash().unwrap(),
                        err
                    ),
                }

                ok((network, hard_chain))
            },
        )
        .and_then(|_| ok(()));

    let loop_fut_state = state_receiver
        .fold(
            (network.clone(), state_chain),
            |(network, state_chain), (addr, block)| {
                debug!("Received StateBlock {:?}", block.block_hash().unwrap());
                let chain_result = {
                    let mut chain = state_chain.chain.write();
                    chain.append_block(block.clone())
                };

                match chain_result {
                    Ok(()) => {
                        // Forward block
                        let packet =
                            ForwardBlock::new(Arc::new(BlockWrapper::StateBlock(block)));
                        
                        network
                            .send_to_all_except(&addr, &packet.to_bytes())
                            .unwrap();
                    }
                    Err(err) => info!(
                        "Chain Error for block {:?}: {:?}",
                        block.block_hash().unwrap(),
                        err
                    ),
                }

                ok((network, state_chain))
            },
        )
        .and_then(|_| ok(()));

    tokio::spawn(loop_fut_hard);
    tokio::spawn(loop_fut_state);
}
