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
use crate::interface::NetworkInterface;
use crate::peer::ConnectionType;
use crate::client_request::ClientRequest;
use chrono::prelude::*;
use crypto::{SecretKey as Sk, Signature};
use triomphe::Arc;
use async_trait::async_trait;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;

/// The type id of a packet.
pub type PacketType = u8;

#[async_trait]
/// Generic packet interface
pub trait Packet {
    /// The type of the packet.
    const PACKET_TYPE: PacketType;

    /// Serializes a `Packet` to its binary format.
    fn to_bytes(&self) -> Vec<u8>;

    /// Attempts to deserialize a `Packet` from a given binary string.
    fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>, NetworkErr>;

    /// Callback that handles a `Packet` after it has been parsed.
    async fn handle<N: NetworkInterface, S: AsyncWrite + AsyncWriteExt + Unpin + Send + Sync>(
        network: &mut N,
        socket: &S,
        peer: &SocketAddr,
        packet: Arc<Self>,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr>;

    /// Returns `Some(_)` if the packet is an initial packet
    /// in a client request. Returns `None` otherwise.
    fn to_client_request(&self) -> Option<ClientRequest>;

    /// Attempts to start a client protocol flow using the packet.
    /// 
    /// This should return an `Err(_)` if the packet cannot start 
    /// a client protocol flow. 
    async fn start_client_protocol_flow<N: NetworkInterface, S: AsyncWrite + AsyncWriteExt + AsyncRead + AsyncReadExt + Unpin + Send + Sync>(
      &self, 
      network: &N, 
      sock: &S
    ) -> Result<(), NetworkErr> {
        Err(NetworkErr::CannotStartProtocolFlow)
    }

    /// Attempts to start a server protocol flow using the packet.
    /// 
    /// This should return an `Err(_)` if the packet cannot start 
    /// a server protocol flow. 
    async fn start_server_protocol_flow<N: NetworkInterface, S: AsyncWrite + AsyncWriteExt + AsyncRead + AsyncReadExt + Unpin + Send + Sync>(
      &self, 
      network: &N, 
      sock: &S
    ) -> Result<(), NetworkErr> {
        Err(NetworkErr::CannotStartProtocolFlow)
    }
}
