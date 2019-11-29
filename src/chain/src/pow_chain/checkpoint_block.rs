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

use crate::block::Block;
use crate::chain::*;
use crate::pow_chain::PowChainState;
use crate::types::*;
use hashbrown::HashSet;
use account::NormalAddress;
use crypto::{NodeId, Signature, SecretKey as Sk};
use bin_tools::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use crypto::Hash;
use crypto::PublicKey;
use lazy_static::*;
use miner::{Proof, PROOF_SIZE};
use std::boxed::Box;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Clone, Debug)]
/// A block belonging to the `PowChain`.
pub struct CheckpointBlock {
    /// The height of the block.
    height: u64,

    /// The address that will collect the
    /// rewards earned by the miner.
    collector_address: NormalAddress,

    /// The `NodeId` belonging to the miner.
    miner_id: NodeId,

    /// The `Signature` corresponding to the miner's id.
    miner_signature: Option<Signature>,

    /// The hash of the parent block.
    parent_hash: Option<Hash>,

    /// The block's proof of work
    proof: Proof,

    /// The hash of the block.
    hash: Option<Hash>,

    /// The timestamp of the block.
    timestamp: DateTime<Utc>,
}

impl PartialEq for CheckpointBlock {
    fn eq(&self, other: &CheckpointBlock) -> bool {
        // This only makes sense when the block is received
        // when the node is a server i.e. when the block is
        // guaranteed to have a hash because it already passed
        // the parsing stage.
        self.block_hash().unwrap() == other.block_hash().unwrap()
    }
}

impl Eq for CheckpointBlock {}

impl HashTrait for CheckpointBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_hash().unwrap().hash(state);
    }
}

impl Block for CheckpointBlock {
    type ChainState = PowChainState;

    fn genesis() -> Arc<CheckpointBlock> {
        unimplemented!();
    }

    fn is_genesis(&self) -> bool {
        unimplemented!();
    }

    fn genesis_state() -> PowChainState {
        PowChainState::genesis()
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn block_hash(&self) -> Option<Hash> {
        self.hash.clone()
    }

    fn parent_hash(&self) -> Option<Hash> {
        self.parent_hash.clone()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn after_write() -> Option<Box<dyn FnMut(Arc<CheckpointBlock>)>> {
        let fun = |block| {};
        Some(Box::new(fun))
    }

    fn append_condition(
        block: Arc<CheckpointBlock>,
        mut chain_state: Self::ChainState,
        branch_type: BranchType,
    ) -> Result<Self::ChainState, ChainErr> {
        let block_hash = block.block_hash().unwrap();

        // Verify the signature of the miner over the block
        if !block.verify_miner_sig() {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::BadMinerSig));
        }  

        // TODO: Validate difficulty. Issue #118
        let difficulty = 0;

        #[cfg(test)]
        let edge_bits = 0;

        #[cfg(not(test))]
        let edge_bits = chain_state.edge_bits;

        // Validate proof of work
        if let Err(_) = miner::verify(
            &block_hash.0,
            block.proof.nonce as u32,
            difficulty,
            edge_bits,
            &block.proof,
        ) {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::BadProof));
        }

        Ok(chain_state)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let ts = self.timestamp.to_rfc3339();
        let timestamp = ts.as_bytes();
        let timestamp_len = timestamp.len() as u8;

        buf.write_u8(Self::BLOCK_TYPE).unwrap();
        buf.write_u8(timestamp_len).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.hash.unwrap().0);
        buf.extend_from_slice(&self.parent_hash.unwrap().0);
        buf.extend_from_slice(&self.collector_address.to_bytes());
        buf.extend_from_slice(&(&self.miner_id.0).0);
        buf.extend_from_slice(&self.miner_signature.as_ref().unwrap().to_bytes());
        buf.extend_from_slice(&self.proof.to_bytes());
        buf.extend_from_slice(&timestamp);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<CheckpointBlock>, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let block_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        if block_type != Self::BLOCK_TYPE {
            return Err("Bad block type");
        }

        rdr.set_position(1);

        let address_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        rdr.set_position(2);

        let timestamp_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        rdr.set_position(3);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        buf.drain(..11);

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 1");
        };

        let parent_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 3");
        };

        let collector_address = if buf.len() > 33 as usize {
            let addr: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&addr) {
                Ok(address) => address,
                _ => return Err("Incorrect address field"),
            }
        } else {
            return Err("Incorrect packet structure 5");
        };

        let miner_id = if buf.len() > 32 as usize {
            let id: Vec<u8> = buf.drain(..32).collect();

            match NodeId::from_bytes(&id) {
                Ok(address) => address,
                _ => return Err("Incorrect miner id field"),
            }
        } else {
            return Err("Incorrect packet structure 6");
        };

        let miner_signature = if buf.len() > 64 as usize {
            let sig: Vec<u8> = buf.drain(..64).collect();

            match Signature::from_bytes(&sig) {
                Ok(address) => address,
                _ => return Err("Incorrect signature field"),
            }
        } else {
            return Err("Incorrect packet structure 7");
        };

        let proof = if buf.len() > 1 + 8 + 8 * PROOF_SIZE {
            let proof: Vec<u8> = buf.drain(..(1 + 8 + 8 * PROOF_SIZE)).collect();

            match Proof::from_bytes(&proof) {
                Ok(proof) => proof,
                _ => return Err("Incorrect proof field"),
            }
        } else {
            return Err("Incorrect packet structure 8");
        };

        let timestamp = if buf.len() == timestamp_len as usize {
            match std::str::from_utf8(&buf) {
                Ok(utf8) => match DateTime::<Utc>::from_str(utf8) {
                    Ok(timestamp) => timestamp,
                    Err(_) => return Err("Invalid block timestamp"),
                },
                Err(_) => return Err("Invalid block timestamp"),
            }
        } else {
            return Err("Invalid block timestamp");
        };

        Ok(Arc::new(CheckpointBlock {
            timestamp,
            collector_address,
            miner_id,
            proof,
            hash: Some(hash),
            parent_hash: Some(parent_hash),
            miner_signature: Some(miner_signature),
            height,
        }))
    }
}

impl CheckpointBlock {
    pub const BLOCK_TYPE: u8 = 1;

    pub fn new(
        parent_hash: Option<Hash>,
        collector_address: NormalAddress,
        ip: SocketAddr,
        height: u64,
        proof: Proof,
        miner_id: NodeId,
    ) -> CheckpointBlock {
        CheckpointBlock {
            parent_hash,
            collector_address,
            miner_id,
            height,
            hash: None,
            miner_signature: None,
            proof,
            timestamp: Utc::now(),
        }
    }

    pub fn sign_miner(&mut self, sk: &Sk) {
        let message = self.compute_sign_message();
        let sig = crypto::sign(&message, sk);
        self.miner_signature = Some(sig);
    }

    pub fn verify_miner_sig(&self) -> bool {
        let message = self.compute_sign_message();
        crypto::verify(&message, self.miner_signature.as_ref().unwrap(), &self.miner_id.0)
    }

    pub fn compute_hash(&mut self) {
        let message = self.compute_hash_message();
        let hash = crypto::hash_slice(&message);

        self.hash = Some(hash);
    }

    pub fn verify_hash(&self) -> bool {
        let message = self.compute_hash_message();
        let oracle = crypto::hash_slice(&message);

        self.hash.unwrap() == oracle
    }

    fn compute_hash_message(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let encoded_height = encode_be_u64!(self.height);

        buf.extend_from_slice(&encoded_height);

        if let Some(ref parent_hash) = self.parent_hash {
            buf.extend_from_slice(&parent_hash.0);
        }

        buf.extend_from_slice(&self.collector_address.to_bytes());
        buf.extend_from_slice(&(self.miner_id.0).0);
        buf.extend_from_slice(&self.proof.to_bytes());

        if let Some(ref miner_signature) = self.miner_signature {
            buf.extend_from_slice(&miner_signature.to_bytes());
        }

        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());
        buf
    }

    fn compute_sign_message(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let encoded_height = encode_be_u64!(self.height);

        buf.extend_from_slice(&encoded_height);

        if let Some(ref parent_hash) = self.parent_hash {
            buf.extend_from_slice(&parent_hash.0);
        } else {
            unreachable!();
        }

        buf.extend_from_slice(&self.collector_address.to_bytes());
        buf.extend_from_slice(&(self.miner_id.0).0);
        buf.extend_from_slice(&self.proof.to_bytes());
        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());
        buf
    }
}

use quickcheck::*;

impl Arbitrary for CheckpointBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> CheckpointBlock {
        CheckpointBlock {
            height: Arbitrary::arbitrary(g),
            collector_address: Arbitrary::arbitrary(g),
            parent_hash: Some(Arbitrary::arbitrary(g)),
            hash: Some(Arbitrary::arbitrary(g)),
            miner_id: Arbitrary::arbitrary(g),
            miner_signature: Some(Arbitrary::arbitrary(g)),
            proof: Proof::random(PROOF_SIZE),
            timestamp: Utc::now(),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::test_helpers::*;
//     use graphlib::VertexId;
//     use rayon::prelude::*;
//     use hashbrown::{HashMap, HashSet};
//     use parking_lot::Mutex;

//     macro_rules! is_enum_variant {
//         ($v:expr, $p:pat) => (
//             if let $p = $v { true } else { false }
//         );
//     }

//     quickcheck! {
//         fn append_condition_integration() -> bool {
//             let (pow_chain, _) = init_test_chains();
//             let test_set = chain_test_set(50, 10, false, false);
//             let MAX_ITERATIONS = 8000;
//             let mut cur_iterations = 0;

//             let pow_graph = test_set.pow_graph.clone();
//             let state_graph = test_set.state_graph.clone();

//             let mut pow_blocks: HashSet<Arc<CheckpointBlock>> = test_set.pow_blocks.iter().cloned().collect();
//             let pow_appended: Arc<Mutex<HashSet<Arc<CheckpointBlock>>>> = Arc::new(Mutex::new(HashSet::new()));
//             let pow_non_canonical: Arc<Mutex<HashSet<Arc<CheckpointBlock>>>> = Arc::new(Mutex::new(HashSet::new()));
//             let pow_rejected: Arc<Mutex<HashMap<Arc<CheckpointBlock>, ChainErr>>> = Arc::new(Mutex::new(HashMap::new()));
//             let pow_appended_clone = pow_appended.clone();
//             let pow_non_canonical_clone = pow_non_canonical.clone();
//             let pow_rejected_clone = pow_rejected.clone();
//             let mut pow_to_append = Vec::new();

//             // Un-comment this to add failed test cases to
//             // `src/test/failed_cases`. These can then be
//             // visualized by using graphviz.
//             std::panic::set_hook(Box::new(move |_| {
//                 use std::path::Path;
//                 use std::fs::File;

//                 let mut pow_graph = pow_graph.clone();
//                 let pow_appended = pow_appended_clone.lock();
//                 let pow_non_canonical = pow_non_canonical_clone.lock();
//                 let pow_rejected = pow_rejected_clone.lock();

//                 let case_id = crypto::gen_bytes(12);
//                 let case_id = hex::encode(&case_id);

//                 println!("Adding failed case with id {} to src/test/failed_cases...", &case_id);

//                 let timestamp = Utc::now();
//                 let timestamp = timestamp.to_rfc3339();
//                 let failed_path = Path::new("src/test/failed_cases");
//                 let dir_name = format!("src/test/failed_cases/{}-{}", timestamp, case_id);
//                 let dir_path = Path::new(&dir_name);

//                 // Create failed cases dir if it does not exist
//                 if std::fs::metadata(&failed_path).is_err() {
//                     std::fs::create_dir(failed_path).unwrap();
//                 }

//                 // Create graphs dir
//                 std::fs::create_dir(&dir_path).unwrap();

//                 // Assemble graphs paths
//                 let pow_path = dir_path.join("pow_graph.dot");
//                 let state_path = dir_path.join("state_graph.dot");

//                 let pow_hm: HashMap<VertexId, Arc<CheckpointBlock>> = pow_graph
//                     .vertices()
//                     .cloned()
//                     .map(|id| (id, pow_graph.fetch(&id).unwrap().clone()))
//                     .collect();

//                 // Map labels so we can see which blocks were appended
//                 pow_graph.map_labels(|id, _| {
//                     let block = pow_hm.get(id).unwrap();
//                     let block_hash = block.block_hash().unwrap();
//                     let suffix = if pow_appended.contains(block) {
//                         "CANONICAL".to_owned()
//                     } else if let Some(r) = pow_rejected.get(block) {
//                         map_reason(r)
//                     } else if pow_non_canonical.contains(block) {
//                         "NON_CANONICAL".to_owned()
//                     } else {
//                         "NOT_APPENDED".to_owned()
//                     };

//                     let block_hash = format!("{}", block_hash);
//                     let block_hash = &block_hash[..6];

//                     format!("N_{}_H{}_{}", block_hash, block.height(), suffix)
//                 });

//                 // Create files
//                 let mut pow_f = File::create(pow_path).unwrap();
//                 let mut state_f = File::create(state_path).unwrap();

//                 // Write graphs data
//                 pow_graph.to_dot("pow_chain", &mut pow_f).unwrap();
//                 state_graph.to_dot("state_chain", &mut state_f).unwrap();
//             }));

//             // For each iteration, try to append as many blocks as possible
//             loop {
//                 if cur_iterations >= MAX_ITERATIONS {
//                     //panic!("Exceeded iterations limit");
//                     break;
//                 }

//                 for b in pow_blocks.iter() {
//                     match pow_chain.append_block(b.clone()) {
//                         Ok(_) => {
//                             pow_to_append.push(b.clone());
//                         }

//                         Err(reason) => {
//                             if let ChainErr::BadHeight = reason {
//                                 // Do nothing
//                             } else {
//                                 let mut pow_rejected = pow_rejected.lock();
//                                 pow_rejected.insert(b.clone(), reason);
//                             }
//                         }
//                     }
//                 }

//                 for b in pow_to_append.iter() {
//                     let block_hash = b.block_hash().unwrap();

//                     pow_blocks.remove(b);

//                     if pow_chain.is_canonical(&block_hash) {
//                         let mut pow_appended = pow_appended.lock();
//                         pow_appended.insert(b.clone());
//                     } else {
//                         let mut pow_non_canonical = pow_non_canonical.lock();
//                         pow_non_canonical.insert(b.clone());
//                     }
//                 }

//                 //std::thread::sleep_ms(140);

//                 if pow_blocks.is_empty() {
//                     break;
//                 }

//                 cur_iterations += 1;
//             }

//             {
//                 let pow_chain = pow_chain.chain.read();

//                 assert_eq!(pow_chain.canonical_tip_height(), test_set.pow_canonical.height());
//             }

//             true
//         }

//         fn it_verifies_hashes(block: CheckpointBlock) -> bool {
//             let mut block = block.clone();

//             assert!(!block.verify_hash());

//             block.compute_hash();
//             block.verify_hash()
//         }

//         fn serialize_deserialize(block: CheckpointBlock) -> bool {
//             CheckpointBlock::from_bytes(&CheckpointBlock::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap();

//             true
//         }
//     }

//     fn map_reason(reason: &ChainErr) -> String {
//         let base = "REJECTED";

//         match reason {
//             ChainErr::AlreadyInChain => {
//                 format!("{}_DUPLICATE", base)
//             }

//             ChainErr::BadHeight => {
//                 format!("{}_BADHEIGHT", base)
//             }

//             ChainErr::CannotRewindPastRootBlock => {
//                 format!("{}_CANNOTREWIND", base)
//             }

//             ChainErr::InvalidParent => {
//                 format!("{}_BADPARENT", base)
//             }

//             ChainErr::NoCheckpointFound => {
//                 format!("{}_NOCHECKPOINT", base)
//             }

//             ChainErr::NoParentHash => {
//                 format!("{}_NOPARENTHASH", base)
//             }

//             ChainErr::NoSuchBlock => {
//                 format!("{}_NOBLOCK", base)
//             }

//             ChainErr::TooManyOrphans => {
//                 format!("{}_ORPHANSFULL", base)
//             }

//             ChainErr::BadAppendCondition(reason) => {
//                 let reason = match reason {
//                     AppendCondErr::BadEasyHeight => {
//                         "BADHEIGHT"
//                     }

//                     AppendCondErr::BadEpoch => {
//                         "BADEPOCH"
//                     }

//                     AppendCondErr::BadProof => {
//                         "BADPROOF"
//                     }

//                     AppendCondErr::BadTransaction => {
//                         "BADTX"
//                     }

//                     AppendCondErr::BadValidator => {
//                         "BADVALIDATOR"
//                     }

//                     AppendCondErr::Default => {
//                         "DEFAULT"
//                     }

//                     AppendCondErr::NoBlockFound => {
//                         "NOBLOCK"
//                     }
//                 };

//                 format!("{}_BADAPPCOND_{}", base, reason)
//             }
//         }
//     }
// }
