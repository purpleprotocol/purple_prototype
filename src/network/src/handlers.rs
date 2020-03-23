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

use crate::packet::Packet;
use crate::packets::ForwardBlock;
use crate::priority::NetworkPriority;
use crate::{Network, NetworkInterface};
use chain::*;
use std::net::SocketAddr;
use triomphe::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;
use tokio::time::Interval;

/// Listens for blocks on chain receivers and
/// forwards them to their respective chains.
pub fn start_block_listeners(
    network: Network,
    pow_chain: PowChainRef,
    mut pow_receiver: Receiver<(SocketAddr, Arc<PowBlock>)>,
) {
    let loop_fut_pow = async move {
        loop {
            if let Some((addr, block)) = pow_receiver.recv().await {
                debug!("Received PowBlock {:?}", block.block_hash().unwrap());
                let chain_result = {
                    let mut chain = pow_chain.chain.write();
                    chain.append_block(block.clone())
                };

                match chain_result {
                    Ok(()) => {
                        // Forward block
                        let packet = ForwardBlock::new(block);
                        network
                            .send_to_all_except(&addr, &packet.to_bytes(), NetworkPriority::Medium)
                            .unwrap();
                    }
                    Err(err) => info!(
                        // TODO: Handle chain errors
                        "Chain Error for block {:?} with height {}: {:?}",
                        block.block_hash().unwrap(),
                        block.height(),
                        err
                    ),
                }
            } else {
                info!("PowReceiver closed!");
                break;
            }
        }
    };

    tokio::spawn(loop_fut_pow);
}
