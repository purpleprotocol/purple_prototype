/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

use std::sync::Arc;
use std::sync::mpsc::Receiver;
use tokio::executor::Spawn;
use futures::prelude::*;
use std::net::SocketAddr;
use crate::{NetworkInterface, Network};
use crate::packets::ForwardBlock;
use parking_lot::Mutex;
use futures::future::{self, ok, loop_fn, Loop, FutureResult};
use chain::*;

/// Listens for blocks on chain receivers and 
/// forwards them to their respective chains.
pub fn start_block_listeners(
    network: Arc<Mutex<Network>>,
    easy_chain: EasyChainRef, 
    hard_chain: HardChainRef,
    state_chain: StateChainRef,
    easy_receiver: Receiver<(SocketAddr, Arc<EasyBlock>)>,
    hard_receiver: Receiver<(SocketAddr, Arc<HardBlock>)>,
    state_receiver: Receiver<(SocketAddr, Arc<StateBlock>)>,
) {
    let loop_fut_easy = loop_fn((network.clone(), easy_receiver, easy_chain), |state| {
        {
            let (network, easy_rec, easy) = &state;

            if let Ok((addr, block)) = easy_rec.try_recv() {
                debug!("Received EasyBlock {:?}", block.block_hash().unwrap());
                let easy_chain = &easy.chain;
                let chain_result = {
                    let mut chain = easy_chain.write();
                    chain.append_block(block.clone())
                };

                match chain_result {
                    Ok(()) => {
                        let network = network.lock();

                        // Forward block
                        let mut packet = ForwardBlock::new(network.our_node_id().clone(), Arc::new(BlockWrapper::EasyBlock(block)));
                        network.send_to_all_unsigned_except(&addr, &mut packet).unwrap();
                    }
                    Err(err) => info!("Chain Error for block {:?}: {:?}", block.block_hash().unwrap(), err)
                }
            }
        }

        Ok(Loop::Continue(state))
    });

    let loop_fut_hard = loop_fn((network.clone(), hard_receiver, hard_chain), |state| {
        {
            let (network, hard_rec, hard) = &state;

            if let Ok((addr, block)) = hard_rec.try_recv() {
                debug!("Received HardBlock {:?}", block.block_hash().unwrap());
                let hard_chain = &hard.chain;
                let chain_result = {
                    let mut chain = hard_chain.write();
                    chain.append_block(block.clone())
                };
                
                match chain_result {
                    Ok(()) => {
                        let network = network.lock();

                        // Forward block
                        let mut packet = ForwardBlock::new(network.our_node_id().clone(), Arc::new(BlockWrapper::HardBlock(block)));
                        network.send_to_all_unsigned_except(&addr, &mut packet).unwrap();
                    }
                    Err(err) => info!("Chain Error for block {:?}: {:?}", block.block_hash().unwrap(), err)
                }
            }
        }

        Ok(Loop::Continue(state))
    });

    let loop_fut_state = loop_fn((network, state_receiver, state_chain), |state| {
        {
            let (network, state_rec, state) = &state;

            if let Ok((addr, block)) = state_rec.try_recv() {
                debug!("Received StateBlock {:?}", block.block_hash().unwrap());
                let state_chain = &state.chain;
                let chain_result = {
                    let mut chain = state_chain.write();
                    chain.append_block(block.clone())
                };
                
                match chain_result {
                    Ok(()) => {
                        let network = network.lock();

                        // Forward block
                        let mut packet = ForwardBlock::new(network.our_node_id().clone(), Arc::new(BlockWrapper::StateBlock(block)));
                        network.send_to_all_unsigned_except(&addr, &mut packet).unwrap();
                    }
                    Err(err) => info!("Chain Error for block {:?}: {:?}", block.block_hash().unwrap(), err)
                }
            }
        }

        Ok(Loop::Continue(state))
    });

    tokio::spawn(loop_fut_easy);
    tokio::spawn(loop_fut_hard);
    tokio::spawn(loop_fut_state);
}