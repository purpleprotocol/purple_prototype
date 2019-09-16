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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkErr {
    /// The format of the packet is invalid
    BadFormat,

    /// The packet has an invalid signature
    BadSignature,

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

    /// The provided header is invalid
    BadHeader,

    /// The network version found in the packet is invalid
    BadVersion,

    /// We have connected to ourselves
    SelfConnect,

    /// Could not send a packet. Maybe the outbound buffer is full? 
    /// Or maybe the peer does not have an encryption key ready?
    CouldNotSend,

    /// Could not acknowledge the packet. 
    AckErr,

    /// The sender is in an invalid state for this operation
    SenderStateErr,

    /// The peer's session has expired
    SessionExpired,
}
