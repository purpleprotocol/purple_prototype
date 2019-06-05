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

use crate::peer::ConnectionType;
use crate::interface::NetworkInterface;
use crate::node_id::NodeId;
use crate::error::NetworkErr;
use crate::packet::Packet;
use chrono::prelude::*;
use std::sync::Arc;
use std::net::SocketAddr;
use byteorder::{ReadBytesExt, WriteBytesExt};
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};

#[derive(Debug, Clone, PartialEq)]
pub struct RequestPeers {
    node_id: NodeId,
    timestamp: DateTime<Utc>,
    signature: Option<Signature>
}

impl RequestPeers {
    pub const PACKET_TYPE: u8 = 2;

    pub fn new(node_id: NodeId) -> RequestPeers {
        RequestPeers {
            node_id: node_id,
            timestamp: Utc::now(),
            signature: None,
        }
    }
}

impl Packet for RequestPeers {
    fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    fn verify_sig(&self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.node_id.0),
            None => false,
        }
    }

    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<RequestPeers>, NetworkErr> {
        unimplemented!();
    }

    fn handle<N: NetworkInterface>(network: &mut N, addr: &SocketAddr, packet: &RequestPeers, conn_type: ConnectionType) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

fn assemble_sign_message(obj: &RequestPeers) -> Vec<u8> {
    unimplemented!();
}
