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

use crate::error::NetworkErr;
use crate::validation::receiver::Receiver;
use crate::protocol_flow::ping_pong::receiver_state::PingPongReceiverState;
use crate::packets::{Ping, Pong};

#[derive(Debug, Default)]
pub struct PingPongReceiver {
    state: PingPongReceiverState,
}

impl Receiver<Ping, Pong> for PingPongReceiver {
    /// Attempts to receive a packet and outputs a new packet
    /// to be sent back if the receiver is able to receive a
    /// packet. 
    fn receive(&mut self, packet: &Ping) -> Result<Pong, NetworkErr> {
        if let PingPongReceiverState::Ready = self.state {
            Ok(Pong::new(packet.nonce))
        } else {
            unreachable!();
        }
    }
    
    /// Returns true if the receiver is able to receive packets.
    fn can_receive(&self) -> bool {
        true
    }
}