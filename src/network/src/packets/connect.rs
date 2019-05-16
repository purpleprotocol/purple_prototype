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

use byteorder::{ReadBytesExt, WriteBytesExt};
use crypto::{PublicKey as Pk, SecretKey as Sk, Signature, KxPublicKey as KxPk};
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq)]
pub struct Connect {
    node_id: Pk,
    kx_key: KxPk,
    signature: Option<Signature>,
}

impl Connect {
    pub const PACKET_TYPE: u8 = 1;

    pub fn new(node_id: Pk, kx_key: KxPk) -> Connect {
        Connect {
            node_id: node_id,
            kx_key: kx_key,
            signature: None,
        }
    }

    /// Signs the packet with the given secret key.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        // Attach signature to struct
        self.signature = Some(signature);
    }

    /// Verifies the signature of the packet.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig.clone(), self.node_id),
            None => false,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(129);
        let packet_type: u8 = Self::PACKET_TYPE;

        let mut signature = if let Some(signature) = &self.signature {
            signature.inner_bytes()
        } else {
            panic!("Signature field is missing");
        };

        let node_id = &self.node_id.0;
        let kx_key = &self.kx_key.0;

        // Connect packet structure:
        // 1) Packet type(1)   - 8bits
        // 2) Key exchange pk  - 32byte binary
        // 3) Node id          - 32byte binary
        // 4) Signature        - 64byte binary
        buffer.write_u8(packet_type).unwrap();
        buffer.append(&mut kx_key.to_vec());
        buffer.append(&mut node_id.to_vec());
        buffer.append(&mut signature);

        buffer
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Connect, &'static str> {
        let mut rdr = Cursor::new(bin.to_vec());
        let packet_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad packet type");
        };

        if packet_type != Self::PACKET_TYPE {
            return Err("Bad packet type");
        }

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..1).collect();

        let kx_key = if buf.len() > 32 as usize {
            let kx_key_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&kx_key_vec);

            KxPk(b)
        } else {
            return Err("Incorrect packet structure");
        };

        let node_id = if buf.len() > 32 as usize {
            let node_id_vec: Vec<u8> = buf.drain(..32).collect();
            let mut b = [0; 32];

            b.copy_from_slice(&node_id_vec);

            Pk(b)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() == 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();
            Signature::new(&sig_vec)
        } else {
            return Err("Incorrect packet structure");
        };

        let packet = Connect {
            node_id: node_id,
            kx_key: kx_key,
            signature: Some(signature),
        };

        Ok(packet)
    }
}

fn assemble_sign_message(obj: &Connect) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    let kx_key = obj.kx_key.0;
    let node_id = obj.node_id.0;

    buf.append(&mut kx_key.to_vec());
    buf.append(&mut node_id.to_vec());

    buf
}

#[cfg(test)]
use quickcheck::Arbitrary;

#[cfg(test)]
use crypto::Identity;

#[cfg(test)]
impl Arbitrary for Connect {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Connect {
        let (pk, _) = crypto::gen_kx_keypair();
        let id = Identity::new();

        Connect {
            node_id: *id.pkey(),
            kx_key: pk,
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::collections::VecDeque;
    use parking_lot::Mutex;
    use hashbrown::HashMap;
    use crate::interface::NetworkInterface;
    use crate::mock::MockNetwork;
    use crate::node_id::NodeId;

    #[test]
    fn it_successfuly_performs_connect_handshake() {
        let mailboxes = Arc::new(Mutex::new(HashMap::new()));
        let addr1 = crate::random_socket_addr();
        let addr2 = crate::random_socket_addr();
        let (pk1, sk1) = crypto::gen_keypair();
        let (pk2, sk2) = crypto::gen_keypair(); 
        let n1 = NodeId::from_pkey(pk1);
        let n2 = NodeId::from_pkey(pk2);

        let mut address_mappings = HashMap::new();

        address_mappings.insert(addr1.clone(), n1.clone());
        address_mappings.insert(addr2.clone(), n2.clone());

        mailboxes.lock().insert(n1.clone(), VecDeque::new());
        mailboxes.lock().insert(n2.clone(), VecDeque::new());

        let network1 = MockNetwork::new(n1.clone(), addr1, "test_network".to_owned(), sk1, mailboxes.clone(), address_mappings.clone());
        let network2 = MockNetwork::new(n2.clone(), addr2, "test_network".to_owned(), sk2, mailboxes.clone(), address_mappings.clone());
        let network1 = Arc::new(Mutex::new(network1));
        let network1_c = network1.clone();
        let network2 = Arc::new(Mutex::new(network2));
        let network2_c = network2.clone();

        // Peer 1 listener thread
        thread::Builder::new()
            .name("peer1".to_string())
            .spawn(move || MockNetwork::start_receive_loop(network1))
            .unwrap();

        // Peer 2 listener thread
        thread::Builder::new()
            .name("peer2".to_string())
            .spawn(move || MockNetwork::start_receive_loop(network2))
            .unwrap();

        // Attempt to connect the first peer to the second
        network1_c.lock().connect(&addr2).unwrap();

        // Pause main thread for a bit before
        // making assertions.
        thread::sleep(Duration::from_millis(2));

        let network1 = network1_c.lock();
        let network2 = network2_c.lock();

        assert!(network1.peers.get(&addr2).is_some());
        assert!(network2.peers.get(&addr1).is_some());

        let peer2 = network1.peers.get(&addr2).unwrap().clone();
        let peer1 = network2.peers.get(&addr1).unwrap().clone();
        
        // Check if the peers have the same session keys
        assert_eq!(peer1.rx.unwrap(), peer2.tx.unwrap());
        assert_eq!(peer2.rx.unwrap(), peer1.tx.unwrap());
    }

    quickcheck! {
        fn serialize_deserialize(tx: Connect) -> bool {
            tx == Connect::from_bytes(&Connect::to_bytes(&tx)).unwrap()
        }

        fn verify_signature(id1: Identity, id2: Identity) -> bool {
            let id = Identity::new();
            let (pk, _) = crypto::gen_kx_keypair();
            let mut packet = Connect {
                node_id: *id.pkey(),
                kx_key: pk,
                signature: None
            };

            packet.sign(id.skey().clone());
            packet.verify_sig()
        }

    }
}
