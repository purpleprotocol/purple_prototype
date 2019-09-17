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
use crate::protocol_flow::request_peers::sender_state::RequestPeersSenderState;
use crate::validation::sender::Sender;

#[derive(Debug, Default)]
pub struct RequestPeersSender {
    state: RequestPeersSenderState,
}

impl Sender<RequestPeers, SendPeers> for RequestPeersSender {
    fn send(&mut self) -> Result<RequestPeers, NetworkErr> {
        unimplemented!();
    }

    fn acknowledge(&mut self, packet: &SendPeers) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn can_send(&self) -> bool {
        self.state == RequestPeersSenderState::Ready
    }

    fn reset(&mut self) {
        self.state = RequestPeersSenderState::Ready;
    }
}