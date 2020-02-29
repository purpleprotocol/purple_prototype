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
use crate::packets::{RequestPeers, SendPeers};
use crate::protocol_flow::request_peers::sender_state::RequestPeersSenderState;
use crate::validation::sender::Sender;

#[derive(Debug, Default)]
pub struct RequestPeersSender {
    state: RequestPeersSenderState,
}

impl Sender<RequestPeers, SendPeers, u8> for RequestPeersSender {
    fn send(&mut self, requested_peers: u8) -> Result<RequestPeers, NetworkErr> {
        if let RequestPeersSenderState::Ready = self.state {
            let request_peers = RequestPeers::new(requested_peers);

            // Await a `SendPeers` with the generated nonce
            self.state = RequestPeersSenderState::Waiting(request_peers.nonce, requested_peers);

            Ok(request_peers)
        } else {
            Err(NetworkErr::CouldNotSend)
        }
    }

    fn acknowledge(&mut self, packet: &SendPeers) -> Result<(), NetworkErr> {
        if let RequestPeersSenderState::Waiting(nonce, requested_peers) = self.state {
            if nonce == packet.nonce && packet.peers.len() <= requested_peers as usize {
                // Reset state
                self.state = RequestPeersSenderState::Ready;

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
        self.state == RequestPeersSenderState::Ready
    }

    fn reset(&mut self) {
        self.state = RequestPeersSenderState::Ready;
    }
}
