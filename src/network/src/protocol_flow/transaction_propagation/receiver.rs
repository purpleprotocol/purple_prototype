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
use crate::interface::NetworkInterface;
use crate::protocol_flow::transaction_propagation::receiver_state::TxReceiverState;
use crate::protocol_flow::transaction_propagation::outbound::OutboundPacket;
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::validation::receiver::Receiver;
use std::net::SocketAddr;

#[derive(Debug, Default)]
pub struct TxReceiver {
    state: TxReceiverState,
}

impl Receiver<OutboundPacket, InboundPacket> for TxReceiver {
    fn receive<N: NetworkInterface>(&mut self, _network: &N, _sender: &SocketAddr, packet: &OutboundPacket) -> Result<InboundPacket, NetworkErr> {
        if let TxReceiverState::Ready = self.state {
            unimplemented!();
        } else {
            unreachable!();
        }
    }

    fn done(&self) -> bool {
        unimplemented!();
    }

    fn can_receive(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        unimplemented!();
    }
}
