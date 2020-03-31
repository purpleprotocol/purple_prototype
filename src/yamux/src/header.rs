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

use crate::message_type::MessageType;

#[derive(Debug, Clone)]
pub struct Header {
    /// The message type field.
    message_type: MessageType,

    /// Flags field.
    /// 
    /// Supported flags:
    /// 0x1 SYN - Signals the start of a new stream. May be sent with a data or window update message. Also sent with a ping to indicate outbound.
    /// 0x2 ACK - Acknowledges the start of a new stream. May be sent with a data or window update message. Also sent with a ping to indicate response.
    /// 0x4 FIN - Performs a half-close of a stream. May be sent with a data message or window update.
    /// 0x8 RST - Reset a stream immediately. May be sent with a data or window update message.
    flags: u16,
    
    /// The id of the stream. The client uses odd ids and the server even ones.
    stream_id: u32,
}