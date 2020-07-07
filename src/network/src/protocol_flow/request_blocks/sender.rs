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

use crate::error::NetworkErr;
use crate::packets::{RequestBlocks, SendBlocks};
use crate::protocol_flow::request_blocks::sender_state::RequestBlocksSenderState;
use crate::validation::sender::Sender;
use crypto::Hash;

#[derive(Debug, Default)]
pub struct RequestBlocksSender {
    state: RequestBlocksSenderState,
}

#[derive(Debug, Clone, Copy)]
pub enum Order {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub struct RequestBlocksSenderArgs {
    requested_blocks: u8,
    from: Hash,
}

impl Sender<RequestBlocks, SendBlocks, RequestBlocksSenderArgs> for RequestBlocksSender {
    fn send(&mut self, args: RequestBlocksSenderArgs) -> Result<RequestBlocks, NetworkErr> {
        if let RequestBlocksSenderState::Ready = self.state {
            let request_blocks = RequestBlocks::new(args.requested_blocks, args.from);

            // Await a `SendBlocks` with the generated nonce
            self.state = RequestBlocksSenderState::Waiting(request_blocks.nonce, args);

            Ok(request_blocks)
        } else {
            Err(NetworkErr::CouldNotSend)
        }
    }

    fn acknowledge(&mut self, packet: &SendBlocks) -> Result<(), NetworkErr> {
        if let RequestBlocksSenderState::Waiting(nonce, args) = self.state {
            if nonce == packet.nonce && packet.blocks.len() <= args.requested_blocks as usize {
                // Reset state
                self.state = RequestBlocksSenderState::Ready;

                Ok(())
            } else {
                Err(NetworkErr::AckErr)
            }
        } else {
            Err(NetworkErr::SenderStateErr)
        }
    }

    fn done(&self) -> bool {
        unimplemented!();
    }

    fn can_send(&self) -> bool {
        self.state == RequestBlocksSenderState::Ready
    }

    fn reset(&mut self) {
        self.state = RequestBlocksSenderState::Ready;
    }
}
