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
use std::boxed::Box;
use std::io::Cursor;
use transactions::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Heartbeat {
    node_id: NodeId,
    stamp: Stamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    transactions: Vec<Box<Tx>>,
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
    /// 8) Stamp         - Binary of stamp length
    /// 9) Transactions  - Binary of txs length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
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
            signature
        } else {
            return Err("Signature field is missing");
        };

        let mut transactions: Vec<Vec<u8>> = Vec::with_capacity(self.transactions.len());

        // Serialize transactions
        for tx in &self.transactions {
            match (*tx).to_bytes() {
                Ok(tx) => transactions.push(tx),
                Err(_) => return Err("Bad transaction"),
            }
        }

        let node_id = &(&&self.node_id.0).0;
        let mut transactions: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&transactions);
        let mut stamp: Vec<u8> = self.stamp.to_bytes();

        let txs_len = transactions.len();
        let stamp_len = stamp.len();

        buffer.write_u8(event_type).unwrap();
        buffer.write_u16::<BigEndian>(stamp_len as u16).unwrap();
        buffer.write_u32::<BigEndian>(txs_len as u32).unwrap();

        buffer.append(&mut node_id.to_vec());
        buffer.append(&mut root_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.inner_bytes());
        buffer.append(&mut stamp);
        buffer.append(&mut transactions);

        Ok(buffer)
    }

    /// Deserializes a heartbeat struct from a byte array
    pub fn from_bytes(bin: &[u8]) -> Result<Heartbeat, &'static str> {
        let mut rdr = Cursor::new(bin.to_vec());
        let event_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad event type");
        };

        if event_type != 0 {
            return Err("Bad event type");
        }

        let stamp_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad stamp len");
        };

        let txs_len = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err("Bad transaction len");
        };

        // Consume cursor
        let mut buf = rdr.into_inner();

        let node_id = if buf.len() > 32 as usize {
            let mut node_id = [0; 32];
            let node_id_vec = buf.split_off(31);

            node_id.copy_from_slice(&node_id_vec);

            NodeId(PublicKey(node_id))
        } else {
            return Err("Incorrect packet structure");
        };

        let root_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec = buf.split_off(31);

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec = buf.split_off(31);

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec = buf.split_off(63);

            Signature::new(&sig_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let stamp = if buf.len() > stamp_len as usize {
            let stamp_bin = buf.split_off(stamp_len as usize - 1);

            if let Ok(stamp) = Stamp::from_bytes(&stamp_bin) {
                stamp
            } else {
                return Err("Bad stamp");
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let transactions = if buf.len() == txs_len as usize {
            let ser_txs: Vec<Vec<u8>> = rlp::decode_list(&buf);
            let mut txs: Vec<Box<Tx>> = Vec::new();

            for tx in ser_txs {
                let tx_type = &tx[0];

                match *tx_type {
                    1 => {
                        let deserialized = match Call::from_bytes(&tx) {
                            Ok(result) => result,
                            Err(_)     => return Err("Invalid call transaction")
                        };

                        txs.push(Box::new(Tx::Call(deserialized)));
                    },
                    _ => return Err("Bad transaction type"),
                }
            }

            txs
        } else {
            return Err("Incorrect packet structure");
        };

        let heartbeat = Heartbeat {
            node_id: node_id,
            root_hash: Some(root_hash),
            hash: Some(hash),
            signature: Some(signature),
            stamp: stamp,
            transactions: transactions,
        };

        Ok(heartbeat)
    }
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
impl Arbitrary for Heartbeat {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Heartbeat {
        Heartbeat {
            node_id: Arbitrary::arbitrary(g),
            root_hash: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
            stamp: Arbitrary::arbitrary(g),
            transactions: Arbitrary::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(tx: Heartbeat) -> bool {
            tx == Heartbeat::from_bytes(&Heartbeat::to_bytes(&tx).unwrap()).unwrap()
        }
    }
}