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
use crate::packet::Packet;
use crate::peer::ConnectionType;
use byteorder::{ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use crypto::NodeId;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct AcceptConnection {
    /// The node id of the requester
    node_id: NodeId,

    /// The packet's timestamp
    timestamp: DateTime<Utc>,

    /// Packet signature
    signature: Option<Signature>,
}

impl AcceptConnection {
    pub const PACKET_TYPE: u8 = 6;

    pub fn new(node_id: NodeId) -> AcceptConnection {
        AcceptConnection {
            node_id: node_id,
            timestamp: Utc::now(),
            signature: None,
        }
    }
}

impl Packet for AcceptConnection {
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

    fn from_bytes(bytes: &[u8]) -> Result<Arc<AcceptConnection>, NetworkErr> {
        unimplemented!();
    }

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &AcceptConnection,
        conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        if !packet.verify_sig() {
            return Err(NetworkErr::BadSignature);
        }

        

        unimplemented!();
    }
}

fn assemble_sign_message(obj: &AcceptConnection) -> Vec<u8> {
    unimplemented!();
}
