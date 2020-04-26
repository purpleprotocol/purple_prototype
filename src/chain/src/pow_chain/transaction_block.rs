/*
  Copyright (C) 2018-2020 The Purple Core Developers.
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
use crate::pow_chain::chain_state::BlockType;
use crate::pow_chain::PowChainState;
use crate::types::*;
use account::NormalAddress;
use bin_tools::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use constants::*;
use crypto::PublicKey;
use crypto::{Hash, ShortHash};
use crypto::{NodeId, SecretKey as Sk, Signature};
use hashbrown::HashSet;
use lazy_static::*;
use miner::{Proof, PROOF_SIZE};
use parking_lot::RwLock;
use patricia_trie::{Trie, TrieDB, TrieDBMut, TrieMut};
use persistence::{Codec, DbHasher, PersistentDb};
use std::boxed::Box;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::str::FromStr;
use transactions::Tx;
use triomphe::Arc;

#[derive(Clone, Debug)]
/// A block belonging to the `PowChain`.
pub struct TransactionBlock {
    /// The height of the block.
    pub height: u64,

    /// The `NodeId` belonging to the miner.
    pub miner_id: NodeId,

    /// The `Signature` corresponding to the miner's id.
    pub miner_signature: Option<Signature>,

    /// The hash of the parent block.
    pub parent_hash: Hash,

    /// The hash of the block.
    pub hash: Option<Hash>,

    /// Checksums of all the block's pieces
    pub tx_checksums: Option<Vec<ShortHash>>,

    /// Sizes of all the pieces
    pub pieces_sizes: Option<Vec<usize>>,

    /// Root hash of all transactions in the block
    pub tx_root: Option<ShortHash>,

    /// Merkle root hash of the state trie
    pub state_root: Option<ShortHash>,

    /// Block transaction list. This is `None` if we only
    /// have the block header.
    pub transactions: Option<Arc<RwLock<Vec<Arc<Tx>>>>>,

    /// The timestamp of the block.
    pub timestamp: DateTime<Utc>,
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
            return Err(ChainErr::BadAppendCondition(
                AppendCondErr::DoesntAcceptBlockType,
            ));
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
                    let trie =
                        TrieDB::<DbHasher, Codec>::new(&chain_state.db, &chain_state.state_root)
                            .unwrap();
                    tx.validate(&trie)
                };

                if validation_result {
                    let mut trie = TrieDBMut::<DbHasher, Codec>::from_existing(
                        &mut chain_state.db,
                        &mut chain_state.state_root,
                    )
                    .unwrap();
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
        let tx_checksums = self.tx_checksums.as_ref().unwrap();
        let pieces_sizes = self.pieces_sizes.as_ref().unwrap();

        buf.write_u8(Self::BLOCK_TYPE).unwrap();
        buf.write_u8(timestamp_len).unwrap();
        buf.write_u8(tx_checksums.len() as u8).unwrap();
        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.parent_hash.0);
        buf.extend_from_slice(&self.state_root.unwrap().0);
        buf.extend_from_slice(&self.tx_root.unwrap().0);
        buf.extend_from_slice(&(&self.miner_id.0).0);
        buf.extend_from_slice(&self.miner_signature.as_ref().unwrap().to_bytes());
        buf.extend_from_slice(&timestamp);

        for (i, checksum) in tx_checksums.iter().enumerate() {
            buf.write_u32::<BigEndian>(pieces_sizes[i] as u32).unwrap();
            buf.extend_from_slice(&checksum.0);
        }

        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Arc<TransactionBlock>, &'static str> {
        let mut rdr = Cursor::new(bytes);
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

        let pieces_count = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad pieces count");
        };

        let max_pieces = MAX_TX_SET_SIZE / MAX_PIECE_SIZE;

        if pieces_count as usize > max_pieces {
            return Err("Pieces count is too large!");
        }

        rdr.set_position(3);

        let height = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad height");
        };

        if bytes.len()
            != 11
                + timestamp_len as usize
                + 32 * 2
                + crypto::SHORT_HASH_BYTES * 2
                + 64
                + pieces_count as usize * 12
        {
            return Err("Invalid packet length");
        }

        let parent_hash = {
            let mut hash = [0; 32];
            hash.copy_from_slice(&bytes[11..43]);

            Hash(hash)
        };

        let state_root = {
            let mut hash = [0; crypto::SHORT_HASH_BYTES];
            hash.copy_from_slice(&bytes[43..51]);

            ShortHash(hash)
        };

        let tx_root = {
            let mut hash = [0; crypto::SHORT_HASH_BYTES];
            hash.copy_from_slice(&bytes[51..59]);

            ShortHash(hash)
        };

        let miner_id =
            NodeId::from_bytes(&bytes[59..91]).map_err(|_| "Incorrect miner id field")?;
        let miner_signature =
            Signature::from_bytes(&bytes[91..155]).map_err(|_| "Incorrect signature field")?;
        let utf8 = std::str::from_utf8(&bytes[155..(155 + timestamp_len as usize)])
            .map_err(|_| "Invalid block timestamp")?;
        let timestamp = DateTime::<Utc>::from_str(utf8).map_err(|_| "Invalid block timestamp")?;

        let mut tx_checksums = Vec::with_capacity(pieces_count as usize);
        let mut pieces_sizes = Vec::with_capacity(pieces_count as usize);

        for i in 0..pieces_count as usize {
            let mut hash_bytes = [0; 8];
            let start_i = 155 + timestamp_len as usize;
            let end_i = 167 + timestamp_len as usize;
            let i = i * 12;
            let start_i = i + start_i;
            let end_i = i + end_i;
            let mut reader = Cursor::new(&bytes[start_i..(start_i + 4)]);

            let piece_size = reader
                .read_u32::<BigEndian>()
                .map_err(|_| "Invalid piece size")?;
            let piece_size = piece_size as usize;

            if piece_size > MAX_PIECE_SIZE || piece_size == 0 {
                return Err("Invalid piece size!");
            }

            hash_bytes.copy_from_slice(&bytes[(start_i + 4)..end_i]);
            tx_checksums.push(ShortHash(hash_bytes));
            pieces_sizes.push(piece_size);
        }

        let mut block = TransactionBlock {
            timestamp,
            miner_id,
            state_root: Some(state_root),
            tx_root: Some(tx_root),
            tx_checksums: Some(tx_checksums),
            pieces_sizes: Some(pieces_sizes),
            hash: None,
            parent_hash,
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
            tx_checksums: None,
            pieces_sizes: None,
            state_root: None,
            tx_root: None,
            hash: None,
            miner_signature: None,
            transactions: None,
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
        crypto::verify(
            &message,
            self.miner_signature.as_ref().unwrap(),
            &self.miner_id.0,
        )
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

    fn compute_sign_message(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let ts = self.timestamp.to_rfc3339();
        let timestamp = ts.as_bytes();
        let tx_checksums = self.tx_checksums.as_ref().unwrap();
        let sizes = self.pieces_sizes.as_ref().unwrap();

        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.parent_hash.0);
        buf.extend_from_slice(&self.state_root.unwrap().0);
        buf.extend_from_slice(&self.tx_root.unwrap().0);
        buf.extend_from_slice(&(&self.miner_id.0).0);
        buf.extend_from_slice(&timestamp);

        for (i, checksum) in tx_checksums.iter().enumerate() {
            buf.write_u32::<BigEndian>(sizes[i] as u32).unwrap();
            buf.extend_from_slice(&checksum.0);
        }

        buf
    }

    fn compute_hash_message(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let ts = self.timestamp.to_rfc3339();
        let timestamp = ts.as_bytes();
        let tx_checksums = self.tx_checksums.as_ref().unwrap();
        let sizes = self.pieces_sizes.as_ref().unwrap();

        buf.write_u64::<BigEndian>(self.height).unwrap();
        buf.extend_from_slice(&self.parent_hash.0);
        buf.extend_from_slice(&self.state_root.unwrap().0);
        buf.extend_from_slice(&self.tx_root.unwrap().0);
        buf.extend_from_slice(&(&self.miner_id.0).0);
        buf.extend_from_slice(&self.miner_signature.as_ref().unwrap().to_bytes());
        buf.extend_from_slice(&timestamp);

        for (i, checksum) in tx_checksums.iter().enumerate() {
            buf.write_u32::<BigEndian>(sizes[i] as u32).unwrap();
            buf.extend_from_slice(&checksum.0);
        }

        buf
    }
}

use quickcheck::*;
use rand::prelude::*;

impl Arbitrary for TransactionBlock {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> TransactionBlock {
        let mut rng = rand::thread_rng();
        let num = rng.gen_range(0, 9);

        let mut block = TransactionBlock {
            tx_checksums: Some(
                (0..num)
                    .into_iter()
                    .map(|_| Arbitrary::arbitrary(g))
                    .collect(),
            ),
            pieces_sizes: Some(
                (0..num)
                    .into_iter()
                    .map(|_| rng.gen_range(1, MAX_PIECE_SIZE))
                    .collect(),
            ),
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
        fn serialize_deserialize(block: Arc<TransactionBlock>) -> bool {
            block == TransactionBlock::from_bytes(&TransactionBlock::from_bytes(&block.to_bytes()).unwrap().to_bytes()).unwrap()
        }

        fn fails_deserialize_if_pieces_count_is_larger_than_allowed(block: TransactionBlock) -> bool {
            let mut rng = rand::thread_rng();
            let mut block = block.clone();
            let mut tx_checksums = block.tx_checksums.as_mut().unwrap();
            let mut pieces_sizes = block.pieces_sizes.as_mut().unwrap();
            let max_pieces = MAX_TX_SET_SIZE / MAX_PIECE_SIZE;

            for i in 0..(max_pieces + 10) {
                tx_checksums.push(crypto::hash_slice(format!("random_hash-{}", i).as_bytes()).to_short());
                pieces_sizes.push(rng.gen_range(1, MAX_PIECE_SIZE));
            }

            block.compute_hash();
            assert_eq!(TransactionBlock::from_bytes(&block.to_bytes()), Err("Pieces count is too large!"));
            true
        }

        fn fails_deserialize_if_piece_size_is_bigger_than_allowed(block: TransactionBlock) -> bool {
            let mut rng = rand::thread_rng();
            let mut block = block.clone();
            let mut pieces_sizes = block.pieces_sizes.as_mut().unwrap();

            if pieces_sizes.len() == 0 {
                return true;
            }

            let random = rng.gen_range(MAX_PIECE_SIZE + 1, MAX_PIECE_SIZE + 100);

            pieces_sizes.pop();
            pieces_sizes.push(random);
            block.compute_hash();

            assert_eq!(TransactionBlock::from_bytes(&block.to_bytes()), Err("Invalid piece size!"));
            true
        }

        fn fails_deserialize_with_0_piece_size(block: TransactionBlock) -> bool {
            let mut block = block.clone();
            let mut pieces_sizes = block.pieces_sizes.as_mut().unwrap();

            if pieces_sizes.len() == 0 {
                return true;
            }

            pieces_sizes.pop();
            pieces_sizes.push(0);
            block.compute_hash();

            assert_eq!(TransactionBlock::from_bytes(&block.to_bytes()), Err("Invalid piece size!"));
            true
        }
    }
}
