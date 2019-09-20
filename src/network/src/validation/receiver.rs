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
use crate::interface::NetworkInterface;
use std::net::SocketAddr;

/// The `Receiver` portion of a protocol flow between two
/// or more packet types. This is modeled as a finite-state
/// machine which receives as input sent messages by a `Sender`
/// and outputs messages that are to be sent back to the `Sender`.
pub trait Receiver<I, O> {
    /// Attempts to receive a packet and outputs a new packet
    /// to be sent back if the receiver is able to receive a
    /// packet.
    fn receive<N: NetworkInterface>(&mut self, network: &N, sender: &SocketAddr, packet: &I) -> Result<O, NetworkErr>;

    /// Returns true if the receiver is able to receive packets.
    fn can_receive(&self) -> bool;

    /// Resets the `Receiver` to its default state.
    fn reset(&mut self);
}
