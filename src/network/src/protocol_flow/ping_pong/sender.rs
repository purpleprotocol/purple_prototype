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
use crate::validation::sender::Sender;
use crate::protocol_flow::ping_pong::sender_state::PingPongSenderState;
use crate::packets::{Ping, Pong};

#[derive(Debug, Default)]
pub struct PingPongSender {
    state: PingPongSenderState,
}

impl Sender<Ping, Pong> for PingPongSender {
    fn send(&mut self) -> Result<Ping, NetworkErr> {
        unimplemented!();
    }

    fn acknowledge(&mut self, packet: &Pong) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn can_send(&self) -> bool {
        self.state == PingPongSenderState::Ready
    }
}

