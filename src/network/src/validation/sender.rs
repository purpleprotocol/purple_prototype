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
use crate::validation::fsm::Fsm;

/// The `Sender` portion of a protocol flow between two
/// or more packet types. This is modeled as a finite-state 
/// machine which outputs messages that are to be sent and
/// receives as input acknowledgements for those messages.
pub trait Sender<O, I>: Fsm<O, I> {
    /// Acknowledges the receival of an output message.
    fn acknowledge(&mut self, message: I) -> Result<(), NetworkErr>;

    /// Attempts to account a new sent packet from the `Sender` and
    /// returns the packet if successful.
    fn send(&mut self) -> Result<O, NetworkErr>;

    /// Returns true if the `Sender` is able to send a packet.
    fn can_send(&self) -> bool;
}