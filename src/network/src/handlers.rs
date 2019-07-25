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

use crate::packets::ForwardBlock;
use crate::{Network, NetworkInterface};
use chain::*;
use futures::future::ok;
use futures::prelude::*;
use parking_lot::Mutex;
use std::net::SocketAddr;
use futures::sync::mpsc::Receiver;
use std::sync::Arc;

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
    let loop_fut_easy = easy_receiver.fold((network.clone(), easy_chain), |(network, easy_chain), (addr, block)| {
        debug!("Received EasyBlock {:?}", block.block_hash().unwrap());
        let chain_result = {
            let mut chain = easy_chain.chain.write();
            chain.append_block(block.clone())
        };

        match chain_result {
            Ok(()) => {
                let network = network.lock();

                // Forward block
                let mut packet = ForwardBlock::new(
                    network.our_node_id().clone(),
                    Arc::new(BlockWrapper::EasyBlock(block)),
                );
                network
                    .send_to_all_unsigned_except(&addr, &mut packet)
                    .unwrap();
            }
            Err(err) => info!(
                "Chain Error for block {:?}: {:?}",
                block.block_hash().unwrap(),
                err
            ),
        }

        ok((network, easy_chain))
    }).and_then(|_| ok(()));

    let loop_fut_hard = hard_receiver.fold((network.clone(), hard_chain), |(network, hard_chain), (addr, block)| {
        debug!("Received HardBlock {:?}", block.block_hash().unwrap());
        let chain_result = {
            let mut chain = hard_chain.chain.write();
            chain.append_block(block.clone())
        };

        match chain_result {
            Ok(()) => {
                let network = network.lock();

                // Forward block
                let mut packet = ForwardBlock::new(
                    network.our_node_id().clone(),
                    Arc::new(BlockWrapper::HardBlock(block)),
                );
                network
                    .send_to_all_unsigned_except(&addr, &mut packet)
                    .unwrap();
            }
            Err(err) => info!(
                "Chain Error for block {:?}: {:?}",
                block.block_hash().unwrap(),
                err
            ),
        }

        ok((network, hard_chain))
    }).and_then(|_| ok(()));

    let loop_fut_state = state_receiver.fold((network.clone(), state_chain), |(network, state_chain), (addr, block)| {
        debug!("Received StateBlock {:?}", block.block_hash().unwrap());
        let chain_result = {
            let mut chain = state_chain.chain.write();
            chain.append_block(block.clone())
        };

        match chain_result {
            Ok(()) => {
                let network = network.lock();

                // Forward block
                let mut packet = ForwardBlock::new(
                    network.our_node_id().clone(),
                    Arc::new(BlockWrapper::StateBlock(block)),
                );
                network
                    .send_to_all_unsigned_except(&addr, &mut packet)
                    .unwrap();
            }
            Err(err) => info!(
                "Chain Error for block {:?}: {:?}",
                block.block_hash().unwrap(),
                err
            ),
        }

        ok((network, state_chain))
    }).and_then(|_| ok(()));

    tokio::spawn(loop_fut_easy);
    tokio::spawn(loop_fut_hard);
    tokio::spawn(loop_fut_state);
}
