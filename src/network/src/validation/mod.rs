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

//! The protocol validation is modeled as a finite state machine
//! which receives as input the type of the packet received by
//! a peer and allows or disallows certain packet types from
//! being sent.
//!
//! For example, a peer cannot send a `Pong` or `SendPeers` packet
//! without first receiving a `Ping` or `RequestPeers` packet.
//!
//! Two finite-state machines are initialized for each peer and for
//! each protocol interaction, a `Sender` and a `Receiver` machines.
//!
//! The outputs of the `Sender` are the inputs of the `Receiver` and
//! vice-versa.

pub mod receiver;
pub mod sender;
pub mod validator;
