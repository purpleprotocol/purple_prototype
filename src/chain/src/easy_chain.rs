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
use crate::easy_block::EasyBlock;
use crate::iterators::easy::EasyBlockIterator;
use bin_tools::*;
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashSet;
use hashdb::HashDB;
use lru::LruCache;
use persistence::PersistentDb;
use std::cell::RefCell;
use std::sync::Arc;

/// Size of the block cache.
const BLOCK_CACHE_SIZE: usize = 20;

/// The easy chain stores blocks that represent buffered
/// validator pool join requests. If a miner wishes to become
/// a validator, it will mine on the easy chain (which has lower
/// difficulty in order to populate the pool more effectively).
///
/// The difficulty of the easy chain grows asimptotically with
/// the number of mined blocks since the last mined block on the
/// hard-chain so that the buffer is rate-limited.
///
/// When a block is mined on the hard chain, all of the miners
/// that have succesfuly mined a block on the easy chain (along
/// with the miner that succesfuly mined a hard block) since
/// the last mined block on the hard one are joined to the pool
/// in one operation.
///
/// Miner rewards on the easy chain are substantially less than the
/// ones on the hard chain, however, miners from the easy chain receive
/// transaction fees as additional reward because they participate in the
/// validator pool.
pub struct EasyChain {
    /// Reference to the database storing the `EasyChain`.
    db: PersistentDb,

    /// The current height of the canonical chain.
    height: usize,

    /// The topmost block in the canonical chain.
    canonical_top: Arc<EasyBlock>,

    /// Cache storing the top blocks descended from the
    /// canonical chain and excluding the actual canonical
    /// top block.
    canonical_tops_cache: HashSet<Arc<EasyBlock>>,

    /// Block lookup cache
    block_cache: RefCell<LruCache<Hash, Arc<EasyBlock>>>,
}

impl EasyChain {
    pub fn new(mut db_ref: PersistentDb) -> EasyChain {
        // TODO: Handle different branches
        let top_key = crypto::hash_slice(b"canonical_top");
        let top_db_res = db_ref.get(&top_key);
        let canonical_top = match top_db_res.clone() {
            Some(top) => {
                let mut buf = [0; 32];
                buf.copy_from_slice(&top);

                let block_bytes = db_ref.get(&Hash(buf)).unwrap();
                Arc::new(EasyBlock::from_bytes(&block_bytes).unwrap())
            }
            None => {
                // TODO: Compute genesis block
                Arc::new(EasyBlock::new(None))
            }
        };

        let canonical_tops_key = crypto::hash_slice(b"canonical_tops");

        // Insert new canonical tops entry if non-existent.
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

                let mut b: HashSet<Arc<EasyBlock>> = HashSet::new();
                b.insert(canonical_top.clone());

                b
            }
        };

        let height_key = crypto::hash_slice(b"canonical_height");
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

        EasyChain {
            canonical_top,
            canonical_tops_cache: canonical_tops,
            height,
            db: db_ref,
            block_cache: RefCell::new(LruCache::new(BLOCK_CACHE_SIZE)),
        }
    }
}

impl<'a> Chain<'a, EasyBlock, EasyBlockIterator<'a>> for EasyChain {
    fn genesis(&self) -> Arc<EasyBlock> {
        unimplemented!();
    }

    fn query(&self, hash: &Hash) -> Option<Arc<EasyBlock>> {
        if let Some(cached) = self.block_cache.borrow_mut().get(hash) {
            Some(cached.clone())
        } else {
            if let Some(stored) = self.db.get(hash) {
                // Store to heap and cache result
                let heap_stored = Arc::new(EasyBlock::from_bytes(&stored).unwrap());
                self.block_cache
                    .borrow_mut()
                    .put(hash.clone(), heap_stored.clone());

                Some(heap_stored)
            } else {
                None
            }
        }
    }

    fn query_by_height(&self, height: usize) -> Option<Arc<EasyBlock>> {
        unimplemented!();
    }

    fn block_height(&self, hash: &Hash) -> Option<usize> {
        unimplemented!();
    }

    fn append_block(&mut self, block: Arc<EasyBlock>) -> Result<(), ChainErr> {
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
    fn canonical_top(&self) -> Arc<EasyBlock> {
        self.canonical_top.clone()
    }

    fn iter_canonical_tops(&'a self) -> EasyBlockIterator<'a> {
        EasyBlockIterator(Box::new(
            self.canonical_tops_cache.iter().map(AsRef::as_ref),
        ))
    }

    fn iter_pending_tops(&'a self) -> EasyBlockIterator<'a> {
        unimplemented!();
    }
}
