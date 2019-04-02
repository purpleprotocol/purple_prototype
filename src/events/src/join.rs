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

use account::NormalAddress;
use bitvec::Bits;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use causality::Stamp;
use crypto::{Hash, PublicKey, Signature};
use network::NodeId;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Join {
    /// The joined `NodeId`
    pub node_id: NodeId,

    /// The stamp of the join event
    pub stamp: Stamp,

    /// The address which will collect the funds
    /// accumulated by the validator.
    pub collector_address: NormalAddress,

    /// The proof of work
    pub proof: Vec<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// The hash of the parent event in the causal graph.
    pub parent_cg_hash: Option<Hash>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// The hash of the parent `Join` event.
    pub parent_join_hash: Option<Hash>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl Join {
    pub const EVENT_TYPE: u8 = 1;

    /// Serializes a heartbeat struct.
    ///
    /// All fields are written in big endian.
    ///
    /// Fields:
    /// 1) Event type(1)      - 8bits
    /// 2) Bitmask            - 8bits
    /// 3) Stamp length       - 16bits
    /// 4) Proof length       - 16bits
    /// 5) Node id            - 32byte binary
    /// 6) Collector address  - 32byte binary
    /// 7) Parent cg hash     - 32byte binary
    /// 8) Parent hash        - 32byte binary
    /// 9) Hash               - 32byte binary
    /// 10) Signature         - 64byte binary
    /// 11) Stamp             - Binary of stamp length
    /// 12) Proof             - Binary of proof length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut bitmask: u8 = 0;
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
        let mut proof: Vec<u8> = rlp::encode_list::<u32, _>(&self.proof);
        let mut stamp: Vec<u8> = self.stamp.to_bytes();
        let collector_address = &self.collector_address.to_bytes();
        let parent_join_hash = if let Some(parent_join_hash) = &self.parent_join_hash {
            Some(&parent_join_hash.0)
        } else {
            None
        };

        let parent_cg_hash = if let Some(parent_cg_hash) = &self.parent_cg_hash {
            Some(&parent_cg_hash.0)
        } else {
            None
        };

        let proof_len = proof.len();
        let stamp_len = stamp.len();

        buffer.write_u8(event_type).unwrap();

        if let Some(_) = parent_cg_hash {
            bitmask.set(0, true);
        } else {
            bitmask.set(0, false);
        }

        if let Some(_) = parent_join_hash {
            bitmask.set(1, true);
        } else {
            bitmask.set(1, false);
        }

        buffer.write_u8(bitmask).unwrap();
        buffer.write_u16::<BigEndian>(stamp_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(proof_len as u16).unwrap();

        buffer.append(&mut node_id.to_vec());
        buffer.append(&mut collector_address.to_vec());

        if let Some(parent_cg_hash) = parent_cg_hash {
            buffer.append(&mut parent_cg_hash.to_vec());
        }

        if let Some(parent_join_hash) = parent_join_hash {
            buffer.append(&mut parent_join_hash.to_vec());
        }

        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.inner_bytes());
        buffer.append(&mut stamp);
        buffer.append(&mut proof);

        Ok(buffer)
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Join, &'static str> {
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

        let bitmask = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad event type");
        };

        rdr.set_position(2);

        let stamp_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad stamp len");
        };

        rdr.set_position(4);

        let proof_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad proof len");
        };

        // Consume cursor
        let mut buf = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..6).collect();

        let node_id = if buf.len() > 32 as usize {
            let mut node_id = [0; 32];
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();

            node_id.copy_from_slice(&node_id_vec);

            NodeId(PublicKey(node_id))
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the node id");
        };

        let collector_address = if buf.len() > 33 as usize {
            let collector_address_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&collector_address_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the collector address");
        };

        let parent_cg_hash = if bitmask.get(0) {
            if buf.len() > 32 as usize {
                let mut hash = [0; 32];
                let hash_vec: Vec<u8> = buf.drain(..32).collect();

                hash.copy_from_slice(&hash_vec);

                Some(Hash(hash))
            } else {
                return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the parent hash");
            }
        } else {
            None
        };

        let parent_join_hash = if bitmask.get(1) {
            if buf.len() > 32 as usize {
                let mut hash = [0; 32];
                let hash_vec: Vec<u8> = buf.drain(..32).collect();

                hash.copy_from_slice(&hash_vec);

                Some(Hash(hash))
            } else {
                return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the parent hash");
            }
        } else {
            None
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

        let stamp = if buf.len() > stamp_len as usize {
            let stamp_bin: Vec<u8> = buf.drain(..stamp_len as usize).collect();

            if let Ok(stamp) = Stamp::from_bytes(&stamp_bin) {
                stamp
            } else {
                return Err("Bad stamp");
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the stamp length");
        };

        let proof = if buf.len() == proof_len as usize {
            let proof: Vec<u32> = rlp::decode_list(&buf);
            proof
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the proof length");
        };

        let join = Join {
            node_id,
            collector_address,
            proof,
            parent_join_hash,
            parent_cg_hash,
            hash: Some(hash),
            signature: Some(signature),
            stamp,
        };

        Ok(join)
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for Join {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Join {
        Join {
            node_id: Arbitrary::arbitrary(g),
            stamp: Arbitrary::arbitrary(g),
            collector_address: Arbitrary::arbitrary(g),
            proof: Arbitrary::arbitrary(g),
            parent_join_hash: Arbitrary::arbitrary(g),
            parent_cg_hash: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Join) -> bool {
            tx == Join::from_bytes(&Join::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}
