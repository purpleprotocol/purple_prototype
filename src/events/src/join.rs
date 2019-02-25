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
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use causality::Stamp;
use crypto::{Hash, PublicKey, Signature};
use network::NodeId;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Join {
    node_id: NodeId,
    stamp: Stamp,
    collector_address: NormalAddress,
    nonce: u64,
    proof: Vec<u32>,
    parent_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl Join {
    pub const EVENT_TYPE: u8 = 1;

    /// Serializes a heartbeat struct.
    ///
    /// All fields are written in big endian.
    ///
    /// Fields:
    /// 1) Event type(1)      - 8bits
    /// 2) Stamp length       - 16bits
    /// 3) Proof length       - 16bits
    /// 4) Nonce              - 32bits
    /// 5) Node id            - 32byte binary
    /// 6) Collector address  - 32byte binary
    /// 7) Parent hash        - 32byte binary
    /// 8) Hash               - 32byte binary
    /// 9) Signature          - 64byte binary
    /// 10) Stamp             - Binary of stamp length
    /// 11) Proof             - Binary of proof length
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
        let mut proof: Vec<u8> = rlp::encode_list::<u32, _>(&self.proof);
        let mut stamp: Vec<u8> = self.stamp.to_bytes();
        let nonce = &self.nonce;
        let collector_address = &self.collector_address.to_bytes();
        let parent_hash = &(&self.parent_hash).0;

        let proof_len = proof.len();
        let stamp_len = stamp.len();

        buffer.write_u8(event_type).unwrap();
        buffer.write_u16::<BigEndian>(stamp_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(proof_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*nonce).unwrap();

        buffer.append(&mut node_id.to_vec());
        buffer.append(&mut collector_address.to_vec());
        buffer.append(&mut parent_hash.to_vec());
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

        let stamp_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad stamp len");
        };

        rdr.set_position(3);

        let proof_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad proof len");
        };

        rdr.set_position(5);

        let nonce = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad nonce");
        };

        // Consume cursor
        let mut buf = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..13).collect();

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

        let parent_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the minimum size for the parent hash");
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
            node_id: node_id,
            collector_address: collector_address,
            nonce: nonce,
            proof: proof,
            parent_hash: parent_hash,
            hash: Some(hash),
            signature: Some(signature),
            stamp: stamp,
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
            nonce: Arbitrary::arbitrary(g),
            proof: Arbitrary::arbitrary(g),
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
        fn serialize_deserialize(tx: Join) -> bool {
            tx == Join::from_bytes(&Join::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}
