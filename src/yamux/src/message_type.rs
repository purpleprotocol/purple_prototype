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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MessageType {
    /// 0x0 Data - Used to transmit data. May transmit zero length payloads depending on the flags.
    Data,

    /// 0x1 Window Update - Used to updated the senders receive window size. This is used to implement per-session flow control.
    WindowUpdate,

    /// 0x2 Ping - Used to measure RTT. It can also be used to heart-beat and do keep-alives over TCP.
    Ping,
    
    /// 0x3 Go Away - Used to close a session.
    GoAway,
}