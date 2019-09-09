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

use crate::error::NetworkErr;
use crate::packet::Packet;
use crate::interface::NetworkInterface;
use crate::peer::ConnectionType;
use chrono::prelude::*;
use crypto::{PublicKey as Pk, SecretKey as Sk, NodeId, Signature};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct Pong {
    node_id: NodeId,
    timestamp: DateTime<Utc>,
    signature: Option<Signature>,
}

impl Pong {
    pub const PACKET_TYPE: u8 = 6;

    pub fn new(node_id: NodeId) -> Pong {
        Pong {
            node_id: node_id,
            timestamp: Utc::now(),
            signature: None,
        }
    }
}

impl Packet for Pong {
    fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    fn verify_sig(&self) -> bool {
        let message = assemble_message(&self);

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

    fn handle<N: NetworkInterface>(
        network: &mut N,
        addr: &SocketAddr,
        packet: &Pong,
        _conn_type: ConnectionType,
    ) -> Result<(), NetworkErr> {
        unimplemented!();
    }

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<Pong>, NetworkErr> {
        unimplemented!();
    }
}

fn assemble_message(obj: &Pong) -> Vec<u8> {
    let node_id = (obj.node_id.0).0;
    let timestamp = obj.timestamp.to_rfc3339();
    let mut buf: Vec<u8> = Vec::with_capacity(1 + 32 + timestamp.len());

    buf.extend_from_slice(&[Pong::PACKET_TYPE]);
    buf.extend_from_slice(&node_id);
    buf.extend_from_slice(timestamp.as_bytes());
    buf
}