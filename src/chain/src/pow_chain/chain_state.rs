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

use crate::chain::ChainErr;
use crate::types::*;
use crate::pow_chain::block::GENESIS_HASH_KEY;
use patricia_trie::{TrieDB, Trie};
use persistence::{PersistentDb, BlakeDbHasher, Codec};
use account::Address;
use crypto::{Hash, NodeId};
use hashbrown::{HashMap, HashSet};
use std::collections::VecDeque;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BlockType {
    Checkpoint,
    Transaction
}

#[derive(Clone, PartialEq, Debug)]
pub struct PowChainState {
    /// Database storing the ledger ephemeral state.
    pub(crate) db: PersistentDb,

    /// The current chain height
    pub(crate) height: u64,

    /// Current difficulty
    pub difficulty: u64,

    /// Current edge bits
    pub(crate) edge_bits: u8,

    /// Which block type is accepted next
    pub(crate) accepts: BlockType,

    /// The current validator's node id. This field
    /// is `None` if we accept checkpoint blocks.
    pub(crate) current_validator: Option<NodeId>,

    /// Number of transaction blocks left that the
    /// current validator is allowed to append. This 
    /// field is `None` if we accept checkpoint blocks.
    pub(crate) txs_blocks_left: Option<u32>,

    /// Root hash of the state trie
    pub(crate) state_root: Hash,

    /// Hash of the last checkpoint block.
    pub last_checkpoint: Hash,
}

impl PowChainState {
    const HEIGHT_KEY: &'static [u8] = b"CHAIN_CURRENT_HEIGHT";
    const DIFFICULTY_KEY: &'static [u8] = b"CHAIN_CURRENT_DIFFICULTY";
    const EDGE_BITS_KEY: &'static [u8] = b"CHAIN_EDGE_BITS";
    const LAST_CHECKPOINT_KEY: &'static [u8] = b"CHAIN_LAST_CHECKPOINT";
    const CURRENT_VALIDATOR_KEY: &'static [u8] = b"CHAIN_CURRENT_VALIDATOR";
    const TXS_BLOCKS_LEFT_KEY: &'static [u8] = b"CHAIN_REMAINING_BLOCKS";

    pub fn genesis(db: PersistentDb) -> Self {
        PowChainState {
            db,
            height: 0,
            difficulty: 0,
            edge_bits: miner::MIN_EDGE_BITS,
            accepts: BlockType::Checkpoint, 
            current_validator: None,
            txs_blocks_left: None,
            state_root: Hash::NULL_RLP,
            last_checkpoint: crypto::hash_slice(GENESIS_HASH_KEY),
        }
    }

    /// Creates a new chain state instance by reloading the state
    /// from an existing `PersistentDb` instance
    pub fn reload(db: PersistentDb) -> Result<Self, &'static str> {
        let mut chain_state = Self::genesis(db.clone());
        let encoded_height = db.retrieve(Self::HEIGHT_KEY).ok_or("Could not retrieve height from disk!")?;
        let height = decode_be_u64!(encoded_height).map_err(|_| "Invalid height stored on disk!")?;
        let encoded_difficulty = db.retrieve(Self::DIFFICULTY_KEY).ok_or("Could not retrieve difficulty from disk!")?;
        let difficulty = decode_be_u64!(encoded_difficulty).map_err(|_| "Invalid difficulty stored on disk!")?;
        let encoded_edge_bits = db.retrieve(Self::EDGE_BITS_KEY).ok_or("Could not retrieve edge bits from disk!")?;
        let edge_bits = decode_u8!(encoded_edge_bits).map_err(|_| "Invalid edge bits stored on disk!")?;
        let last_checkpoint = db.retrieve(Self::LAST_CHECKPOINT_KEY).ok_or("Could not retrieve last checkpoint from disk!")?;
        let last_checkpoint = if last_checkpoint.len() == 32 {
            let mut hash = [0; 32];
            hash.copy_from_slice(&last_checkpoint);
            Hash(hash)
        } else {
            return Err("Invalid last checkpoint stored on disk!");
        };

        let state_root = db.retrieve(PersistentDb::ROOT_HASH_KEY).ok_or("Could not retrieve state root from disk!")?;
        let state_root = if state_root.len() == 32 {
            let mut hash = [0; 32];
            hash.copy_from_slice(&state_root);
            Hash(hash)
        } else {
            return Err("Invalid state root stored on disk!");
        };

        let current_validator = if let Some(validator_id) = db.retrieve(Self::CURRENT_VALIDATOR_KEY) {
            Some(NodeId::from_bytes(&validator_id)?)
        } else {
            None
        };

        let txs_blocks_left = if let Some(txs_blocks_left) = db.retrieve(Self::TXS_BLOCKS_LEFT_KEY) {
            let txs_blocks_left = decode_be_u32!(&txs_blocks_left).map_err(|_| "Invalid blocks left stored on disk!")?;
            Some(txs_blocks_left)
        } else {
            None
        };

        chain_state.height = height;
        chain_state.difficulty = difficulty;
        chain_state.edge_bits = edge_bits;
        chain_state.last_checkpoint = last_checkpoint;
        chain_state.state_root = state_root;

        if let Some(current_validator) = current_validator {
            chain_state.current_validator = Some(current_validator);
            chain_state.accepts = BlockType::Transaction;
        }

        if let Some(txs_blocks_left) = txs_blocks_left {
            assert_eq!(chain_state.accepts, BlockType::Transaction);
            chain_state.txs_blocks_left = Some(txs_blocks_left);
        }

        Ok(chain_state)
    }

    pub fn accepts_checkpoint(&self) -> bool {
        self.accepts == BlockType::Checkpoint
    }

    pub fn accepts_tx(&self) -> bool {
        self.accepts == BlockType::Transaction
    }

    /// Attempts to retrieve the current nonce of the account with 
    /// the given address, returning `None` if it is non-existent.
    pub fn get_account_nonce(&self, address: &Address) -> Option<u64> {
        let trie = TrieDB::<BlakeDbHasher, Codec>::new(&self.db, &self.state_root).unwrap();

        // Calculate nonce key
        //
        // The key of a nonce has the following format:
        // `<account-address>.n`
        let nonce_key = format!("{}.n", address);
        let nonce_key = nonce_key.as_bytes();

        let encoded_nonce = trie.get(&nonce_key).ok()??;
        Some(decode_be_u64!(encoded_nonce).unwrap())
    }
}

impl Flushable for PowChainState {
    fn flush(&mut self) -> Result<(), ChainErr> {
        // Write chain state metadata to the `PersistentDb` instance
        self.db.put(Self::HEIGHT_KEY, &encode_be_u64!(self.height));
        self.db.put(Self::DIFFICULTY_KEY, &encode_be_u64!(self.difficulty));
        self.db.put(Self::EDGE_BITS_KEY, &[self.edge_bits]);
        self.db.put(Self::LAST_CHECKPOINT_KEY, &self.last_checkpoint.0);
        self.db.put(PersistentDb::ROOT_HASH_KEY, &self.state_root.0);
        
        if let Some(current_validator) = &self.current_validator {
            assert_eq!(self.accepts, BlockType::Transaction);
            self.db.put(Self::CURRENT_VALIDATOR_KEY, &(current_validator.0).0);
        }

        if let Some(txs_blocks_left) = &self.txs_blocks_left {
            assert_eq!(self.accepts, BlockType::Transaction);
            self.db.put(Self::TXS_BLOCKS_LEFT_KEY, &encode_be_u32!(*txs_blocks_left));
        }

        // Write reload flag which tells us if the underlying
        // db instance is fresh or not i.e. the reload flag 
        // would be missing.
        if self.db.retrieve(PersistentDb::RELOAD_FLAG).is_none() {
            self.db.put(PersistentDb::RELOAD_FLAG, &[])
        }

        // Flush to disk
        self.db.flush();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;

    #[test]
    fn it_reloads_state_from_disk_no_validator() {
        let mut db = test_helpers::init_tempdb();
        let mut chain_state = PowChainState::genesis(db.clone());
    
        // Override genesis values
        chain_state.height = 10;
        chain_state.difficulty = 6;
        chain_state.edge_bits = 29;
        chain_state.state_root = crypto::hash_slice(b"random_state_root");
        chain_state.last_checkpoint = crypto::hash_slice(b"random_checkpoint");

        // Flush values
        chain_state.flush();
        assert!(chain_state.db.retrieve(PersistentDb::RELOAD_FLAG).is_some());

        let reloaded_state = PowChainState::reload(chain_state.db.clone()).unwrap();
        assert_eq!(reloaded_state, chain_state);
    }

    #[test]
    fn it_reloads_state_from_disk() {
        let mut db = test_helpers::init_tempdb();
        let mut chain_state = PowChainState::genesis(db.clone());
        let identity = Identity::new();
        let node_id = NodeId(*identity.pkey());
    
        // Override genesis values
        chain_state.height = 10;
        chain_state.difficulty = 6;
        chain_state.edge_bits = 29;
        chain_state.state_root = crypto::hash_slice(b"random_state_root");
        chain_state.last_checkpoint = crypto::hash_slice(b"random_checkpoint");
        chain_state.current_validator = Some(node_id);
        chain_state.txs_blocks_left = Some(7);
        chain_state.accepts = BlockType::Transaction;

        // Flush values
        chain_state.flush();
        assert!(chain_state.db.retrieve(PersistentDb::RELOAD_FLAG).is_some());

        let reloaded_state = PowChainState::reload(chain_state.db.clone()).unwrap();
        assert_eq!(reloaded_state, chain_state);
    }
}