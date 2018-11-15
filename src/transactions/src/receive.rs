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

use account::{Address, Balance};
use crypto::{Hash, Signature};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use network::NodeId;
use serde::{Deserialize, Serialize};
use transaction::*;

#[derive(Serialize, Deserialize)]
pub struct Receive {
    src_event: Hash,
    source: Hash,
    receiver: Address,
    sequencer: NodeId,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl Receive {
    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(4)      - 8bits
    /// 2) Source                   - 32byte binary
    /// 3) Source event hash        - 32byte binary
    /// 4) Receiver                 - 32byte binary
    /// 5) Sequencer                - 32byte binary
    /// 6) Hash                     - 32byte binary
    /// 7) Signature                - 64byte binary
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = 4;

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

        let source = &&self.source.0;
        let receiver = &self.receiver.to_bytes();
        let sequencer = &(&&self.sequencer.0).0;
        let src_event = &&self.src_event.0;
        
        buffer.write_u8(tx_type).unwrap();

        buffer.append(&mut source.to_vec());
        buffer.append(&mut src_event.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut sequencer.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());

        Ok(buffer)
    }
}