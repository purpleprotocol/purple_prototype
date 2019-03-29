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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use causality::Stamp;
use crypto::{Hash, PublicKey, Signature};
use network::NodeId;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Leave {
    /// The `NodeId` of the event issuer
    pub node_id: NodeId,

    /// The stamp of the `Leave` event
    pub stamp: Stamp,

    /// The hash of the parent event in the causal graph.
    pub parent_hash: Hash,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl Leave {
    pub const EVENT_TYPE: u8 = 2;

    /// Serializes a heartbeat struct.
    ///
    /// All fields are written in big endian.
    ///
    /// Fields:
    /// 1) Event type(2)      - 8bits
    /// 2) Stamp length       - 16bits
    /// 3) Node id            - 32byte binary
    /// 4) Hash               - 32byte binary
    /// 5) Signature          - 64byte binary
    /// 6) Stamp              - Binary of stamp length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let event_type: u8 = Self::EVENT_TYPE;

        let hash = if let Some(hash) = &self.hash {
            &hash.0
        } else {
            return Err("Hash field is missing");
        };

        let signature = if let Some(signature) = &self.signature {
            signature
        } else {
            return Err("Signature field is missing");
        };

        let node_id = &(&&self.node_id.0).0;
        let parent_hash = &self.parent_hash.0;
        let mut stamp: Vec<u8> = self.stamp.to_bytes();

        let stamp_len = stamp.len();

        buffer.write_u8(event_type).unwrap();
        buffer.write_u16::<BigEndian>(stamp_len as u16).unwrap();

        buffer.append(&mut node_id.to_vec());
        buffer.append(&mut parent_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.inner_bytes());
        buffer.append(&mut stamp);

        Ok(buffer)
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Leave, &'static str> {
        let mut rdr = Cursor::new(bin.to_vec());
        let event_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad event type");
        };

        if event_type != Self::EVENT_TYPE {
            return Err("Bad event type");
        }

        rdr.set_position(1);

        let stamp_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad stamp len");
        };

        // Consume cursor
        let mut buf = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..3).collect();

        let node_id = if buf.len() > 32 as usize {
            let mut node_id = [0; 32];
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();

            node_id.copy_from_slice(&node_id_vec);

            NodeId(PublicKey(node_id))
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the node id");
        };

        let parent_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the hash");
        };

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the hash");
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();

            Signature::new(&sig_vec)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the signature");
        };

        let stamp = if buf.len() == stamp_len as usize {
            let stamp_bin: Vec<u8> = buf.drain(..stamp_len as usize).collect();

            if let Ok(stamp) = Stamp::from_bytes(&stamp_bin) {
                stamp
            } else {
                return Err("Bad stamp");
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the stamp length");
        };

        let leave = Leave {
            node_id,
            stamp,
            parent_hash,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(leave)
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for Leave {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Leave {
        Leave {
            node_id: Arbitrary::arbitrary(g),
            stamp: Arbitrary::arbitrary(g),
            parent_hash: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Leave) -> bool {
            tx == Leave::from_bytes(&Leave::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}
