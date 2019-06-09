/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkErr {
    /// The format of the packet is invalid
    BadFormat,

    /// The connection attempt has failed
    ConnectFailed,

    /// The received `Connect` packet is invalid
    InvalidConnectPacket,

    /// The received packet could not be parsed
    PacketParseErr,

    /// We are not connected to the given peer
    PeerNotFound,

    /// We cannot add more peers since we are
    /// already at the maximum.
    MaximumPeersReached,

    /// We are not connected to any peer.
    NoPeers,

    /// We have received a `SendPeers` packet but we didn't ask for it
    DidntAskForPeers,

    /// We have received more peers than we have requested
    TooManyPeers,

    /// The encryption was not valid
    EncryptionErr,

    /// The CRC32 checksum was invalid
    BadCRC32,

    /// The network version found in the packet is invalid
    BadVersion,
}
