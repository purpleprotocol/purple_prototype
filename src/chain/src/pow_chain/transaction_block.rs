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
use crate::pow_chain::chain_state::BlockType;
use crate::types::*;
use transactions::Tx;
use hashbrown::HashSet;
use parking_lot::RwLock;
use account::NormalAddress;
use crypto::{NodeId, Signature, SecretKey as Sk};
use bin_tools::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use crypto::Hash;
use crypto::PublicKey;
use lazy_static::*;
use patricia_trie::{TrieDBMut, TrieDB, TrieMut, Trie};
use persistence::{PersistentDb, BlakeDbHasher, Codec};
use miner::{Proof, PROOF_SIZE};
use std::boxed::Box;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::str::FromStr;
use std::sync::Arc;

/// The maximum size, in bytes, of a transaction set in a transaction block.
pub const MAX_TX_SET_SIZE: usize = 204800; // 200kb

#[derive(Clone, Debug)]
/// A block belonging to the `PowChain`.
pub struct TransactionBlock {
    /// The height of the block.
    height: u64,

    /// The `NodeId` belonging to the miner.
    miner_id: NodeId,

    /// The `Signature` corresponding to the miner's id.
    miner_signature: Option<Signature>,

    /// The hash of the parent block.
    parent_hash: Hash,

    /// The hash of the block.
    hash: Option<Hash>,

    /// Merkle root hash of all transactions in the block
    tx_root: Option<Hash>,

    /// Merkle root hash of the state trie
    state_root: Option<Hash>,

    /// Block transaction list. This is `None` if we only
    /// have the block header.
    transactions: Option<Arc<RwLock<Vec<Arc<Tx>>>>>,

    /// The timestamp of the block.
    timestamp: DateTime<Utc>,
}

impl PartialEq for TransactionBlock {
    fn eq(&self, other: &TransactionBlock) -> bool {
        // This only makes sense when the block is received
        // when the node is a server i.e. when the block is
        // guaranteed to have a hash because it already passed
        // the parsing stage.
        self.block_hash().unwrap() == other.block_hash().unwrap()
    }
}

impl Eq for TransactionBlock {}

impl HashTrait for TransactionBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_hash().unwrap().hash(state);
    }
}

impl Block for TransactionBlock {
    type ChainState = PowChainState;

    fn genesis() -> Arc<TransactionBlock> {
        unimplemented!();
    }

    fn is_genesis(&self) -> bool {
        unimplemented!();
    }

    fn genesis_state() -> PowChainState {
        unimplemented!();
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn block_hash(&self) -> Option<Hash> {
        self.hash.clone()
    }

    fn parent_hash(&self) -> Hash {
        self.parent_hash.clone()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn after_write() -> Option<Box<dyn FnMut(Arc<TransactionBlock>)>> {
        let fun = |block| {};
        Some(Box::new(fun))
    }

    fn append_condition(
        block: Arc<TransactionBlock>,
        mut chain_state: Self::ChainState,
        branch_type: BranchType,
    ) -> Result<Self::ChainState, ChainErr> {
        // Validation
        let block_hash = block.block_hash().unwrap();

        // Verify the signature of the miner over the block
        if !block.verify_miner_sig() {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::BadMinerSig));
        }  

        // Verify that we accept transaction blocks
        if !chain_state.accepts_tx() {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::DoesntAcceptBlockType));
        }

        if block.height() != chain_state.height + 1 {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::BadHeight));
        }

        assert!(chain_state.current_validator.is_some());
        assert!(chain_state.txs_blocks_left.is_some());

        let current_validator = chain_state.current_validator.as_ref().unwrap().clone();
        let mut txs_blocks_left = chain_state.txs_blocks_left.as_ref().unwrap().clone();

        if current_validator != block.miner_id {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::InvalidMiner));
        }

        if txs_blocks_left == 0 {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::NoTxBlocksLeft));
        }

        // Apply transactions to state
        if let Some(transaction_set) = &block.transactions {
            let transaction_set = transaction_set.read();

            for tx in transaction_set.iter() {
                let validation_result = {
                    let trie = TrieDB::<BlakeDbHasher, Codec>::new(&chain_state.db, &chain_state.state_root).unwrap();
                    tx.validate(&trie)
                };

                if validation_result {
                    let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::from_existing(&mut chain_state.db, &mut chain_state.state_root).unwrap();
                    tx.apply(&mut trie);
                } else {
                    return Err(ChainErr::BadAppendCondition(AppendCondErr::BadTx));
                }
            }
        } else {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::NoTxSet));
        }

        // Verify that our state root matches the one in the block header
        if chain_state.state_root != block.state_root.unwrap() {
            return Err(ChainErr::BadAppendCondition(AppendCondErr::BadStateRoot));
        }

        // Commit
        txs_blocks_left -= 1;

        if txs_blocks_left == 0 {
            chain_state.accepts = BlockType::Checkpoint;
            chain_state.current_validator = None;
            chain_state.txs_blocks_left = None;
        } else {
            chain_state.txs_blocks_left = Some(txs_blocks_left);
        }

        chain_state.height = block.height();
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
        buf.extend_from_slice(&self.parent_hash.0);
        buf.extend_from_slice(&self.tx_root.unwrap().0);
        buf.extend_from_slice(&self.state_root.unwrap().0);
        buf.extend_from_slice(&(&self.miner_id.0).0);
        buf.extend_from_slice(&self.miner_signature.as_ref().unwrap().to_bytes());
        buf.extend_from_slice(&timestamp);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<TransactionBlock>, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let block_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad block type");
        };

        if block_type != Self::BLOCK_TYPE {
            return Err("Bad block type");
        }

        rdr.set_position(1);

        let timestamp_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad timestamp len");
        };

        rdr.set_position(2);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        buf.drain(..10);

        let parent_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 3");
        };

        let tx_root = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure 4");
        };

        let state_root = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
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

        let mut block = TransactionBlock {
            timestamp,
            miner_id,
            tx_root: Some(tx_root),
            state_root: Some(state_root),
            hash: None,
            parent_hash: parent_hash,
            miner_signature: Some(miner_signature),
            transactions: None,
            height,
        };

        block.compute_hash();
        Ok(Arc::new(block))
    }
}

impl TransactionBlock {
    pub const BLOCK_TYPE: u8 = 2;

    pub fn new(
        parent_hash: Hash,
        ip: SocketAddr,
        height: u64,
        proof: Proof,
        miner_id: NodeId,
    ) -> TransactionBlock {
        TransactionBlock {
            parent_hash,
            miner_id,
            height,
            tx_root: None,
            state_root: None,
            hash: None,
            miner_signature: None,
            transactions: None,
            timestamp: Utc::now(),
        }
    }

    pub fn sign_miner(&mut self, sk: &Sk) {
        let message = self.compute_message();
        let sig = crypto::sign(&message, sk);
        self.miner_signature = Some(sig);
    }

    pub fn verify_miner_sig(&self) -> bool {
        let message = self.compute_message();
        crypto::verify(&message, self.miner_signature.as_ref().unwrap(), &self.miner_id.0)
    }

    pub fn compute_hash(&mut self) {
        let message = self.compute_message();
        let hash = crypto::hash_slice(&message);

        self.hash = Some(hash);
    }

    pub fn verify_hash(&self) -> bool {
        let message = self.compute_message();
        let oracle = crypto::hash_slice(&message);

        self.hash.unwrap() == oracle
    }

    fn compute_message(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let encoded_height = encode_be_u64!(self.height);

        buf.extend_from_slice(&encoded_height);
        buf.extend_from_slice(&self.parent_hash.0);
        buf.extend_from_slice(&(self.miner_id.0).0);
        buf.extend_from_slice(&self.timestamp.to_rfc3339().as_bytes());
        buf
    }
}

use quickcheck::*;

impl Arbitrary for TransactionBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> TransactionBlock {
        let mut block = TransactionBlock {
            height: Arbitrary::arbitrary(g),
            parent_hash: Arbitrary::arbitrary(g),
            state_root: Some(Arbitrary::arbitrary(g)),
            tx_root: Some(Arbitrary::arbitrary(g)),
            hash: None,
            miner_id: Arbitrary::arbitrary(g),
            miner_signature: Some(Arbitrary::arbitrary(g)),
            timestamp: Utc::now(),
            transactions: None,
        };

        block.compute_hash();
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn serialize_deserialize(block: TransactionBlock) -> bool {
            TransactionBlock::from_bytes(&TransactionBlock::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap();

            true
        }
    }
}
