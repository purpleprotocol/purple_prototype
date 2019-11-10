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

#[derive(Clone, Debug)]
/// Struct representing the header wrapping a network packet.
pub struct PacketHeader {
    /// The version of the network layer
    pub(crate) network_version: u8,

    /// Whether the packet is a validator pool packet
    pub(crate) is_pool_packet: bool,

    /// The crc32 of the packet data
    pub(crate) crc32: u32,

    /// The size of the packet
    pub(crate) packet_len: u16,
}
