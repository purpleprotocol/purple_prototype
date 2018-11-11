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

use std::boxed::Box;
use causality::Stamp;
use network::NodeId;
use crypto::{Hash, Signature};
use transactions::Tx;
use byteorder::{BigEndian, WriteBytesExt};
use rlp::RlpStream;

#[derive(Serialize, Deserialize)]
pub struct Heartbeat {
    node_id: NodeId,
    stamp: Stamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    transactions: Vec<Box<Tx>>
}

impl Heartbeat {
  /// Serializes a heartbeat struct.
  ///
  /// All fields are written in big endian.
  ///
  /// Fields:
  /// 1) Event type(0) - 8bits
  /// 2) Stamp length  - 16bits
  /// 3) Txs length    - 32bits
  /// 4) Node id       - 32byte binary
  /// 5) Root hash     - 32byte binary
  /// 6) Hash          - 32byte binary
  /// 7) Signature     - 64byte binary
  /// 8) Stamp         - binary of stamp length
  /// 9) Transactions  - binary of txs length
  pub fn serialize(&self) -> Result<Vec<u8>, &'static str> {
    let mut rlp_stream = RlpStream::new();
    let mut buffer: Vec<u8> = Vec::new();
    let event_type: u8 = 0;

    let root_hash = if let Some(root_hash) = &self.root_hash {
      &root_hash.0
    } else {
      return Err("Root hash field is missing");
    };
    
    let hash = if let Some(hash) = &self.hash {
      &hash.0
    } else {
      return Err("Hash field is missing");
    };

    let signature = if let Some(signature) = &self.signature {
      &signature.0
    } else {
      return Err("Signature field is missing");
    };
    
    let mut transactions: Vec<Vec<u8>> = Vec::with_capacity(self.transactions.len());
    
    // Serialize transactions
    for tx in self.transactions {
      match &tx.serialize() {
        Ok(tx) => transactions.push(tx),
        Err(_) => return Err("Bad transaction")
      }
    }

    // Write txs to rlp stream
    for tx in transactions {
      rlp_stream.append(&tx);
    }

    let node_id = &(&&self.node_id.0).0;
    let transactions: Vec<u8> = rlp_stream.out();
    let stamp: Vec<u8> = self.stamp.to_bytes();

    let txs_len = transactions.len();
    let stamp_len = stamp.len();

    buffer.write_u8(event_type).unwrap();
    buffer.write_u16::<BigEndian>(stamp_len as u16).unwrap();
    buffer.write_u32::<BigEndian>(txs_len as u32).unwrap();

    buffer.append(&mut node_id.to_vec());
    buffer.append(&mut root_hash.to_vec());
    buffer.append(&mut hash.to_vec());
    buffer.append(&mut signature.to_vec());
    buffer.append(&mut stamp);
    buffer.append(&mut transactions);

    Ok(buffer)
  }

  /// Deserializes a heartbeat struct from a byte array
  pub fn deserialize(bin: &[u8]) -> Heartbeat {

  }
}