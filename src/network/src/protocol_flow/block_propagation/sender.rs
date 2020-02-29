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
use crate::packets::*;
use crate::protocol_flow::block_propagation::inbound::InboundPacket;
use crate::protocol_flow::block_propagation::outbound::OutboundPacket;
use crate::protocol_flow::block_propagation::sender_state::BlockSenderState;
use crate::validation::sender::Sender;
use crypto::ShortHash;
use std::sync::Arc;
use transactions::Tx;

#[derive(Debug, Default)]
pub struct BlockSender {
    state: BlockSenderState,
}

impl Sender<OutboundPacket, InboundPacket, ()> for BlockSender {
    fn send(&mut self, data: ()) -> Result<OutboundPacket, NetworkErr> {
        unimplemented!();
    }

    fn acknowledge(&mut self, packet: &InboundPacket) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn can_send(&self) -> bool {
        unimplemented!();
    }

    fn done(&self) -> bool {
        self.state == BlockSenderState::Done
    }

    fn reset(&mut self) {
        self.state = BlockSenderState::Ready;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
