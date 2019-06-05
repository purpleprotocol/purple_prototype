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

use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::peer::ConnectionType;
use std::net::SocketAddr;
use std::sync::Arc;
use chrono::prelude::*;
use crypto::{Signature, SecretKey as Sk};

/// Generic packet interface
pub trait Packet {
    /// Signs the packet with the given `SecretKey`.
    fn sign(&mut self, sk: &Sk);

    /// Verifies the validity of the packet's signature.
    fn verify_sig(&self) -> bool;

    /// Serializes a `Packet` to its binary format.
    fn to_bytes(&self) -> Vec<u8>;

    /// Attempts to deserialize a `Packet` from a given binary string.
    fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>, NetworkErr>;

    /// Returns a reference to the signature field of the packet.
    fn signature(&self) -> Option<&Signature>;

    // Returns the timestamp of the packet.
    fn timestamp(&self) -> DateTime<Utc>;

    /// Callback that handles a `Packet` after it has been parsed.
    fn handle<N: NetworkInterface>(network: &mut N, peer: &SocketAddr, packet: &Self, conn_type: ConnectionType) -> Result<(), NetworkErr>;
}