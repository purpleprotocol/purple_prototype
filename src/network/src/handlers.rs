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
use futures::future::{self, ok, loop_fn, Loop, FutureResult};
use chain::*;

/// Listens for blocks on chain receivers and 
/// forwards them to their respective chains.
pub fn start_block_listeners(
    easy_chain: EasyChainRef, 
    hard_chain: HardChainRef,
    easy_receiver: Receiver<Arc<EasyBlock>>,
    hard_receiver: Receiver<Arc<HardBlock>>,
) {
    let loop_fut_easy = loop_fn((easy_receiver, easy_chain), |state| {
        {
            let (easy_rec, easy) = &state;

            if let Ok(block) = easy_rec.try_recv() {
                debug!("Received EasyBlock {:?}", block.block_hash().unwrap());
                let easy_chain = &easy.chain;
                let mut chain = easy_chain.write();
                
                // TODO: Handle chain result
                let _result = chain.append_block(block);
            }
        }

        Ok(Loop::Continue(state))
    });

    let loop_fut_hard = loop_fn((hard_receiver, hard_chain), |state| {
        {
            let (hard_rec, hard) = &state;

            if let Ok(block) = hard_rec.try_recv() {
                debug!("Received HardBlock {:?}", block.block_hash().unwrap());
                let hard_chain = &hard.chain;
                let mut chain = hard_chain.write();
                
                // TODO: Handle chain result
                let _result = chain.append_block(block);
            }
        }

        Ok(Loop::Continue(state))
    });

    tokio::spawn(loop_fut_easy);
    tokio::spawn(loop_fut_hard);
}