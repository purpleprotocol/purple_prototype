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
use crate::protocol_flow::transaction_propagation::sender_state::TxSenderState;
use crate::protocol_flow::transaction_propagation::outbound::OutboundPacket;
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::validation::sender::Sender;


#[derive(Debug, Default)]
pub struct TxSender {
    state: TxSenderState,
}

impl Sender<OutboundPacket, InboundPacket, ()> for TxSender {
    fn send(&mut self, _data: ()) -> Result<OutboundPacket, NetworkErr> {
        unimplemented!();
    }

    fn acknowledge(&mut self, packet: &InboundPacket) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn can_send(&self) -> bool {
        unimplemented!();
    }

    fn done(&self) -> bool {
        unimplemented!();
    }

    fn reset(&mut self) {
        unimplemented!();
    }
}
