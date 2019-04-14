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

use crate::block::Block;
use crate::chain::{Chain, ChainErr};
use crate::easy_chain::chain::EasyChainRef;
use crate::hard_chain::block::HardBlock;
use crate::iterators::hard::HardBlockIterator;
use bin_tools::*;
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashSet;
use hashdb::HashDB;
use lru::LruCache;
use parking_lot::{RwLock, Mutex};
use persistence::PersistentDb;
use std::sync::Arc;
use rlp::*;
use lazy_static::*;

/// Size of the block cache.
const BLOCK_CACHE_SIZE: usize = 20;

/// Blocks with height below the canonical height minus 
/// this number will be rejected.
const MIN_HEIGHT: u64 = 10;

/// Blocks with height below the canonical height minus
/// this number will be rejected.
const MAX_HEIGHT: u64 = 10;

lazy_static! {
    /// Atomic reference count to hard chain genesis block
    static ref GENESIS_RC: Arc<HardBlock> = { Arc::new(HardBlock::genesis()) };

    /// Canonical tips key
    static ref CANONICAL_TIPS_KEY: Hash = { crypto::hash_slice(b"canonical_tips") };
    
    /// Canonical tip block key
    static ref TIP_KEY: Hash = { crypto::hash_slice(b"canonical_tip") };

    /// The key to the canonical height of the chain
    static ref CANONICAL_HEIGHT_KEY: Hash = { crypto::hash_slice(b"canonical_height") };

    /// Key to the tip blocks in the chains that are
    /// disconnected from the canonical chain.
    static ref PENDING_TIPS_KEY: Hash = { crypto::hash_slice(b"pending_tips") };

    /// Key to the head blocks in the chains that are
    /// disconnected from the canonical chain.
    static ref PENDING_HEADS_KEY: Hash = { crypto::hash_slice(b"pending_heads") };
}

#[derive(Clone)]
/// Thread-safe reference to an easy chain and its block cache.
pub struct HardChainRef {
    /// Reference to easy chain.
    pub chain: Arc<RwLock<HardChain>>,

    /// Block lookup cache.
    block_cache: Arc<Mutex<LruCache<Hash, Arc<HardBlock>>>>
}

impl HardChainRef {
    pub fn new(chain: Arc<RwLock<HardChain>>) -> HardChainRef {
        HardChainRef {
            chain,
            block_cache: Arc::new(Mutex::new(LruCache::new(BLOCK_CACHE_SIZE)))
        }
    }

    /// Attempts to fetch a block by its hash from the cache
    /// and if it doesn't succeed it then attempts to retrieve
    /// it from the database.
    pub fn query(&self, hash: &Hash) -> Option<Arc<HardBlock>> {
        let cache_result = {
            let mut cache = self.block_cache.lock();

            if let Some(result) = cache.get(hash) {
                Some(result.clone())
            } else {
                None
            }
        };

        if let Some(result) = cache_result {
            Some(result)
        } else {
            let chain_result = {
                let chain = self.chain.read();
            
                if let Some(result) = chain.query(hash) {
                    Some(result)
                } else {
                    None
                }
            };

            if let Some(result) = chain_result {
                let mut cache = self.block_cache.lock();

                if cache.get(hash).is_none() {
                    // Cache result and then return it
                    cache.put(hash.clone(), result.clone());
                }

                Some(result)
            } else {
                None
            }
        }
    }
}

/// The hard chain stores blocks that represent state can be
/// changes in the validator pool. A block from the hard chain
/// can be thought of as a function which changes the state of
/// the validator pool.
///
/// From the point of view of the validator pool a
/// block mined on the hard chain represents an
/// injection of:
///
/// 1. An additional amount of events that the whole pool can order.
/// 2. Additional validators.
///
/// The pool cannot start ordering events without a block
/// being mined in the hard chain which states the new
/// validators that will be added (miners of the latest
/// easy chain blocks since that last mined hard block),
/// how many events the pool can order in the next round,
/// and what nodes to retire from the pool.
///
/// At the same time, the next hard block cannot be applied
/// to the pool until the pool has either consumed all of
/// their allocated events or until the pool is deemed to be
/// corrupt.
pub struct HardChain {
    /// Reference to the database storing the `HardChain`.
    db: PersistentDb,

    /// Reference to associated easy chain.
    easy_chain: EasyChainRef,

    /// The current height of the chain.
    height: u64,

    /// The tipmost block in the canonical chain.
    canonical_tip: Arc<HardBlock>,

    /// Cache storing the tip blocks descended from the
    /// canonical chain and excluding the actual canonical
    /// tip block.
    canonical_tips_cache: HashSet<Hash>,

    /// Cache storing the tip blocks of chains that are
    /// disconnected from the canonical chain.
    pending_tips_cache: HashSet<Hash>,

    /// Cache storing the head blocks of chains that
    /// are disconnected from the canonical chain.
    pending_heads_parents: HashSet<Hash>,
}

impl HardChain {
    pub fn new(mut db_ref: PersistentDb, easy_chain: EasyChainRef) -> HardChain {
        let tip_db_res = db_ref.get(&TIP_KEY);
        let canonical_tip = match tip_db_res.clone() {
            Some(tip) => {
                let mut buf = [0; 32];
                buf.copy_from_slice(&tip);

                let block_bytes = db_ref.get(&Hash(buf)).unwrap();
                Arc::new(HardBlock::from_bytes(&block_bytes).unwrap())
            }
            None => {
                HardChain::genesis()
            }
        };

        let canonical_tips = match db_ref.get(&CANONICAL_TIPS_KEY) {
            Some(encoded) => {
                parse_hash_list(&encoded)
            }
            None => {
                let b: Vec<Vec<u8>> = vec![canonical_tip.block_hash().unwrap().to_vec()];
                let encoded: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&b);

                db_ref.emplace(
                    CANONICAL_TIPS_KEY.clone(),
                    ElasticArray128::<u8>::from_slice(&encoded),
                );

                let mut b: HashSet<Hash> = HashSet::new();
                b.insert(canonical_tip.block_hash().unwrap().clone());

                b
            }
        };

        // Cache pending tips, if any
        let pending_tips = match db_ref.get(&PENDING_TIPS_KEY) {
            Some(encoded) => {
                parse_hash_list(&encoded)
            }
            None => {
                HashSet::new()
            }
        };

        // Cache pending heads, if any
        let pending_heads = match db_ref.get(&PENDING_HEADS_KEY) {
            Some(encoded) => {
                parse_hash_list(&encoded)
            }
            None => {
                HashSet::new()
            }
        };

        let height = match db_ref.get(&CANONICAL_HEIGHT_KEY) {
            Some(height) => decode_be_u64!(&height).unwrap(),
            None => {
                if tip_db_res.is_none() {
                    // Set 0 height
                    db_ref.emplace(
                        CANONICAL_HEIGHT_KEY.clone(),
                        ElasticArray128::<u8>::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]),
                    );
                }

                0
            }
        };

        let height = height;

        HardChain {
            canonical_tip,
            canonical_tips_cache: canonical_tips,
            pending_heads_parents: pending_heads,
            pending_tips_cache: pending_tips,
            height,
            easy_chain,
            db: db_ref,
        }
    }
}

fn parse_hash_list(bytes: &[u8]) -> HashSet<Hash> {
    let mut b = HashSet::new();
    let rlp = Rlp::new(bytes);

    for slice in rlp.iter() {
        let mut bb: [u8; 32] = [0; 32];
        bb.copy_from_slice(slice.as_raw());

        b.insert(Hash(bb));
    }

    b
}

impl<'a> Chain<'a, HardBlock, HardBlockIterator<'a>> for HardChain {
    fn genesis() -> Arc<HardBlock> {
        GENESIS_RC.clone()
    }

    fn query(&self, hash: &Hash) -> Option<Arc<HardBlock>> {
        if let Some(stored) = self.db.get(hash) {
            // Store to heap
            let heap_stored = Arc::new(HardBlock::from_bytes(&stored).unwrap());
            Some(heap_stored)
        } else {
            None
        }
    }

    fn query_by_height(&self, height: u64) -> Option<Arc<HardBlock>> {
        unimplemented!();
    }

    fn block_height(&self, hash: &Hash) -> Option<u64> {
        unimplemented!();
    }

    fn append_block(&mut self, block: Arc<HardBlock>) -> Result<(), ChainErr> {
        let min_height = if self.height > MIN_HEIGHT {
            self.height - MIN_HEIGHT
        } else {
            1
        };

        if block.height() > self.height + MAX_HEIGHT || block.height() < min_height {
            return Err(ChainErr::BadHeight);
        }

        let tip = &self.canonical_tip;

        // The block must have a parent hash and the parent
        // hash must be equal to that of the current tip
        // in order for it to be considered valid.
        if let Some(parent_hash) = block.parent_hash() {
            // First attempt to place the block after the 
            // tip canonical block.
            if parent_hash == tip.block_hash().unwrap() {
                let block_hash = block.block_hash().unwrap();

                // Place block in the ledger
                self.db.emplace(
                    block_hash.clone(),
                    ElasticArray128::<u8>::from_slice(&block.to_bytes()),
                );

                // Set new tip block
                self.canonical_tip = block.clone();
                let mut height = decode_be_u64!(self.db.get(&CANONICAL_HEIGHT_KEY).unwrap()).unwrap();

                // Increment height
                height += 1;

                // Set new height
                self.height = height;

                // Write new height
                let encoded_height = encode_be_u64!(height);
                self.db.emplace(
                    CANONICAL_HEIGHT_KEY.clone(),
                    ElasticArray128::<u8>::from_slice(&encoded_height),
                );

                // Write block height
                let block_height_key = format!("{}.height", hex::encode(block_hash.to_vec()));
                let block_height_key = crypto::hash_slice(block_height_key.as_bytes());

                self.db.emplace(
                    block_height_key,
                    ElasticArray128::<u8>::from_slice(&encoded_height)
                );

                // Mark new hard chain tip block in easy chain
                let mut easy_chain = self.easy_chain.chain.write();
                easy_chain.set_hard_canonical_tip(&block.block_hash().unwrap()).unwrap();

                Ok(())
            } else {
                // Attempt to first add the block after an already placed block.
                if self.canonical_tips_cache.contains(&parent_hash) {
                    let block_hash = block.block_hash().unwrap();

                    // Place block in the ledger
                    self.db.emplace(
                        block_hash.clone(),
                        ElasticArray128::<u8>::from_slice(&block.to_bytes()),
                    );

                    // Remove parent block from disk stored canonical tips entry
                    let encoded = self.db.get(&CANONICAL_TIPS_KEY).unwrap();
                    let mut cache = parse_hash_list(&encoded);

                    // Attempt to connect disconnected chains to 
                    // the newely appended block.

                    // Remove parent block from cache
                    cache.remove(&parent_hash);

                    // Insert new block in cache
                    cache.insert(block.block_hash().unwrap());

                    // Encode and write new entry to disk
                    let mut rlp = RlpStream::new_list(cache.len());

                    for h in cache.iter() {
                        rlp.append(&h.to_vec());
                    }

                    self.db.emplace(CANONICAL_TIPS_KEY.clone(), ElasticArray128::<u8>::from_slice(&rlp.out()));

                    // Set as new cache
                    self.canonical_tips_cache = cache;

                    // Fetch parent height
                    let parent_height_key = format!("{}.height", hex::encode(parent_hash.to_vec()));
                    let parent_height_key = crypto::hash_slice(parent_height_key.as_bytes());

                    let parent_height = self.db.get(&parent_height_key).unwrap();
                    let parent_height = decode_be_u64!(parent_height).unwrap() + 1;
                    let encoded_height = encode_be_u64!(parent_height);

                    // Write block height
                    let block_height_key = format!("{}.height", hex::encode(block_hash.to_vec()));
                    let block_height_key = crypto::hash_slice(block_height_key.as_bytes());

                    self.db.emplace(
                        block_height_key,
                        ElasticArray128::<u8>::from_slice(&encoded_height)
                    );

                    Ok(())
                } else if self.pending_tips_cache.contains(&parent_hash) {
                    let block_hash = block.block_hash().unwrap();

                    // Place block in the ledger
                    self.db.emplace(
                        block_hash.clone(),
                        ElasticArray128::<u8>::from_slice(&block.to_bytes()),
                    );

                    // Remove parent block from disk stored canonical tips entry
                    let encoded = self.db.get(&PENDING_TIPS_KEY).unwrap();
                    let mut cache = parse_hash_list(&encoded);

                    // Remove parent block from cache
                    cache.remove(&parent_hash);

                    // Insert new block in cache
                    cache.insert(block.block_hash().unwrap());

                    // Encode and write new entry to disk
                    let mut rlp = RlpStream::new_list(cache.len());

                    for h in cache.iter() {
                        rlp.append(&h.to_vec());
                    }

                    self.db.emplace(PENDING_TIPS_KEY.clone(), ElasticArray128::<u8>::from_slice(&rlp.out()));

                    // Set as new cache
                    self.pending_tips_cache = cache;

                    // Fetch parent height
                    let parent_height_key = format!("{}.height", hex::encode(parent_hash.to_vec()));
                    let parent_height_key = crypto::hash_slice(parent_height_key.as_bytes());

                    let parent_height = self.db.get(&parent_height_key).unwrap();
                    let parent_height = decode_be_u64!(parent_height).unwrap() + 1;
                    let encoded_height = encode_be_u64!(parent_height);

                    // Write block height
                    let block_height_key = format!("{}.height", hex::encode(block_hash.to_vec()));
                    let block_height_key = crypto::hash_slice(block_height_key.as_bytes());

                    self.db.emplace(
                        block_height_key,
                        ElasticArray128::<u8>::from_slice(&encoded_height)
                    );

                    Ok(())
                } else {
                    // First attempt to place the block after an existing block
                    match self.db.get(&parent_hash) {
                        Some(encoded) => {
                            unimplemented!();
                        }
                        None => {
                            // Create a new non-canonical chain
                            unimplemented!();
                        }
                    }
                }
            }
        } else {
            Err(ChainErr::NoParentHash)
        }
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn canonical_tip(&self) -> Arc<HardBlock> {
        self.canonical_tip.clone()
    }

    // fn iter_canonical_tips(&'a self) -> HardBlockIterator<'a> {
    //     HardBlockIterator(Box::new(
    //         self.canonical_tips_cache.iter().map(|t| self.query(t).unwrap()).map(AsRef::as_ref),
    //     ))
    // }

    // fn iter_pending_tips(&'a self) -> HardBlockIterator<'a> {
    //     HardBlockIterator(Box::new(
    //         self.pending_tips_cache.iter().map(|t| self.query(t).unwrap()).map(AsRef::as_ref),
    //     ))
    // }
}
