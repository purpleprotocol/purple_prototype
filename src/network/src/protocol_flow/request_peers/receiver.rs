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
use crate::packets::{RequestPeers, SendPeers};
use crate::protocol_flow::request_peers::receiver_state::RequestPeersReceiverState;
use crate::validation::receiver::Receiver;

#[derive(Debug, Default)]
pub struct RequestPeersReceiver {
    state: RequestPeersReceiverState,
}

impl Receiver<RequestPeers, SendPeers> for RequestPeersReceiver {
    /// Attempts to receive a packet and outputs a new packet
    /// to be sent back if the receiver is able to receive a
    /// packet.
    fn receive(&mut self, packet: &RequestPeers) -> Result<SendPeers, NetworkErr> {
        if let RequestPeersReceiverState::Ready = self.state {
            unimplemented!();
            //Ok(SendPeers::new(packet.nonce))
        } else {
            unreachable!();
        }
    }

    /// Returns true if the receiver is able to receive packets.
    fn can_receive(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        unimplemented!();
    }
}