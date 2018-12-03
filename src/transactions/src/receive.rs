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
use crypto::{Hash, Signature, PublicKey, SecretKey as Sk};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use network::NodeId;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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
    pub const TX_TYPE: u8 = 4;

    /// Signs the transaction with the given secret key.
    ///
    /// This function will panic if there already exists
    /// a signature and the address type doesn't match
    /// the signature type.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => { 
                crypto::verify(&message, sig.clone(), self.sequencer.0)
            },
            None => {
                false
            }
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(4)      - 8bits
    /// 2) Source                   - 32byte binary
    /// 3) Source event hash        - 32byte binary
    /// 4) Receiver                 - 33byte binary
    /// 5) Sequencer                - 32byte binary
    /// 6) Hash                     - 32byte binary
    /// 7) Signature                - 64byte binary
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

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
        buffer.append(&mut signature.inner_bytes());

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Receive, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let tx_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        if tx_type != Self::TX_TYPE {
            return Err("Bad transation type");
        }

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..1).collect();

        let source = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let src_event = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 33 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..33).collect();
            
            match Address::from_bytes(&receiver_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let sequencer = if buf.len() > 32 as usize {
            let sequencer_vec: Vec<u8> = buf.drain(..32).collect();
            let mut result = [0; 32];
        
            result.copy_from_slice(&sequencer_vec);

            NodeId(PublicKey(result))
        } else {
            return Err("Incorrect packet structure");
        };

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() == 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64 as usize).collect();

            Signature::new(&sig_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let receive = Receive {
            sequencer: sequencer,
            receiver: receiver,
            src_event: src_event,
            source: source,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(receive)
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &Receive) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let source = &obj.source.0;
    let mut receiver = obj.receiver.to_bytes();
    let sequencer = &(&obj.sequencer.0).0;
    let src_event = &obj.src_event.0;

    // Compose data to hash
    buf.append(&mut source.to_vec());
    buf.append(&mut src_event.to_vec());
    buf.append(&mut receiver);
    buf.append(&mut sequencer.to_vec());
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &Receive) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let source = &obj.source.0;
    let mut receiver = obj.receiver.to_bytes();
    let sequencer = &(&obj.sequencer.0).0;
    let src_event = &obj.src_event.0;

    // Compose data to hash
    buf.append(&mut source.to_vec());
    buf.append(&mut src_event.to_vec());
    buf.append(&mut receiver);
    buf.append(&mut sequencer.to_vec());

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for Receive {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Receive {
        Receive {
            src_event: Arbitrary::arbitrary(g),
            source: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            sequencer: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;

    quickcheck! {
        fn serialize_deserialize(tx: Receive) -> bool {
            tx == Receive::from_bytes(&Receive::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: Receive) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            src_event: Hash,
            source: Hash,
            receiver: Address
        ) -> bool {
            let id = Identity::new();

            let mut tx = Receive {
                sequencer: NodeId(*id.pkey()),
                src_event: src_event,
                source: source,
                receiver: receiver,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}