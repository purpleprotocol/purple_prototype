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
use chain::Block;
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature};
use chrono::prelude::*;
use std::sync::Arc;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardBlock<B: Block> {
    node_id: NodeId,
    block: Arc<B>,
    timestamp: DateTime<Utc>,
    signature: Option<Signature>,
}

impl<B: Block> ForwardBlock<B> {
    pub const PACKET_TYPE: u8 = 4;

    pub fn new(node_id: NodeId, block: Arc<B>) -> ForwardBlock<B> {
        ForwardBlock {
            node_id,
            block,
            timestamp: Utc::now(),
            signature: None
        }
    }
}

impl<B: Block> Packet for ForwardBlock<B> {
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

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn from_bytes(bin: &[u8]) -> Result<Arc<ForwardBlock<B>>, NetworkErr> {
        unimplemented!();
    }

    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn handle<N: NetworkInterface>(network: &mut N, addr: &SocketAddr, packet: &ForwardBlock<B>, conn_type: ConnectionType) -> Result<(), NetworkErr> {
        unimplemented!();
    }
}

fn assemble_message<B: Block>(obj: &ForwardBlock<B>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    let block_hash = obj.block.block_hash().unwrap();
    let node_id = (obj.node_id.0).0;
    let timestamp = obj.timestamp.to_rfc3339();

    buf.extend_from_slice(&[ForwardBlock::<B>::PACKET_TYPE]);
    buf.extend_from_slice(&block_hash.0);
    buf.extend_from_slice(&node_id);
    buf.extend_from_slice(timestamp.as_bytes());

    buf
}