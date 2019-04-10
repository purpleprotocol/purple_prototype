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
use crate::easy_chain::EasyChain;
use crate::hard_block::HardBlock;
use crate::iterators::hard::HardBlockIterator;
use bin_tools::*;
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashSet;
use hashdb::HashDB;
use lru::LruCache;
use parking_lot::RwLock;
use persistence::PersistentDb;
use std::cell::RefCell;
use std::sync::Arc;

/// Size of the block cache.
const BLOCK_CACHE_SIZE: usize = 20;

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
    easy_chain: Arc<RwLock<EasyChain>>,

    /// The current height of the chain.
    height: usize,

    /// The topmost block in the canonical chain.
    canonical_top: Arc<HardBlock>,

    /// Cache storing the top blocks descended from the
    /// canonical chain and excluding the actual canonical
    /// top block.
    canonical_tops_cache: HashSet<Arc<HardBlock>>,

    /// Block lookup cache
    block_cache: RefCell<LruCache<Hash, Arc<HardBlock>>>,
}

impl HardChain {
    pub fn new(mut db_ref: PersistentDb, easy_chain: Arc<RwLock<EasyChain>>) -> HardChain {
        // TODO: Handle different branches
        let top_key = crypto::hash_slice(b"top");
        let top_db_res = db_ref.get(&top_key);
        let canonical_top = match top_db_res.clone() {
            Some(top) => {
                let mut buf = [0; 32];
                buf.copy_from_slice(&top);

                let block_bytes = db_ref.get(&Hash(buf)).unwrap();
                Arc::new(HardBlock::from_bytes(&block_bytes).unwrap())
            }
            None => {
                let genesis = easy_chain.read().genesis();

                // TODO: Compute genesis block
                Arc::new(HardBlock::new(None, genesis.block_hash().unwrap()))
            }
        };

        let canonical_tops_key = crypto::hash_slice(b"canonical_tops");

        let canonical_tops = match db_ref.get(&canonical_tops_key) {
            Some(encoded) => {
                unimplemented!();
            }
            None => {
                let b: Vec<Vec<u8>> = vec![canonical_top.block_hash().unwrap().to_vec()];
                let encoded: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&b);

                db_ref.emplace(
                    canonical_tops_key,
                    ElasticArray128::<u8>::from_slice(&encoded),
                );

                let mut b: HashSet<Arc<HardBlock>> = HashSet::new();
                b.insert(canonical_top.clone());

                b
            }
        };

        // TODO: Handle different branches with different heights
        let height_key = crypto::hash_slice(b"height");
        let height = match db_ref.get(&height_key) {
            Some(height) => decode_be_u64!(&height).unwrap(),
            None => {
                if top_db_res.is_none() {
                    // Set 0 height
                    db_ref.emplace(
                        height_key,
                        ElasticArray128::<u8>::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]),
                    );
                }

                0
            }
        };

        let height = height as usize;

        HardChain {
            canonical_top,
            canonical_tops_cache: canonical_tops,
            height,
            easy_chain,
            db: db_ref,
            block_cache: RefCell::new(LruCache::new(BLOCK_CACHE_SIZE)),
        }
    }
}

impl<'a> Chain<'a, HardBlock, HardBlockIterator<'a>> for HardChain {
    fn genesis(&self) -> Arc<HardBlock> {
        unimplemented!();
    }

    fn query(&self, hash: &Hash) -> Option<Arc<HardBlock>> {
        if let Some(cached) = self.block_cache.borrow_mut().get(hash) {
            Some(cached.clone())
        } else {
            if let Some(stored) = self.db.get(hash) {
                // Store to heap and cache result
                let heap_stored = Arc::new(HardBlock::from_bytes(&stored).unwrap());
                self.block_cache
                    .borrow_mut()
                    .put(hash.clone(), heap_stored.clone());

                Some(heap_stored)
            } else {
                None
            }
        }
    }

    fn query_by_height(&self, height: usize) -> Option<Arc<HardBlock>> {
        unimplemented!();
    }

    fn block_height(&self, hash: &Hash) -> Option<usize> {
        unimplemented!();
    }

    fn append_block(&mut self, block: Arc<HardBlock>) -> Result<(), ChainErr> {
        let top = &self.canonical_top;

        // The block must have a parent hash and the parent
        // hash must be equal to that of the current top
        // in order for it to be considered valid.
        if let Some(parent_hash) = block.parent_hash() {
            if parent_hash == top.block_hash().unwrap() {
                // Place block in the ledger
                self.db.emplace(
                    block.block_hash().unwrap().clone(),
                    ElasticArray128::<u8>::from_slice(&block.to_bytes()),
                );

                // Set new top block
                self.canonical_top = block;

                // TODO: Handle different branches with different heights
                let height_key = crypto::hash_slice(b"height");
                let mut height = decode_be_u64!(self.db.get(&height_key).unwrap()).unwrap();

                // Increment height
                height += 1;

                // Set new height
                self.height = height as usize;

                // Write new height
                let encoded_height = encode_be_u64!(height);
                self.db.emplace(
                    height_key,
                    ElasticArray128::<u8>::from_slice(&encoded_height),
                );

                Ok(())
            } else {
                Err(ChainErr::InvalidParent)
            }
        } else {
            Err(ChainErr::NoParentHash)
        }
    }

    fn height(&self) -> usize {
        self.height
    }
    fn canonical_top(&self) -> Arc<HardBlock> {
        self.canonical_top.clone()
    }

    fn iter_canonical_tops(&'a self) -> HardBlockIterator<'a> {
        HardBlockIterator(Box::new(
            self.canonical_tops_cache.iter().map(AsRef::as_ref),
        ))
    }

    fn iter_pending_tops(&'a self) -> HardBlockIterator<'a> {
        unimplemented!();
    }
}
