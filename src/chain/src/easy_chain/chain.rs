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
use crate::easy_chain::block::EasyBlock;
use crate::hard_chain::chain::HardChain;
use bin_tools::*;
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::HashSet;
use hashdb::HashDB;
use lru::LruCache;
use parking_lot::{RwLock, Mutex};
use persistence::PersistentDb;
use std::sync::Arc;
use rlp::Rlp;
use lazy_static::*;

/// Size of the block cache.
const BLOCK_CACHE_SIZE: usize = 20;

lazy_static! {
    /// Atomic reference count to easy chain genesis block
    static ref GENESIS_RC: Arc<EasyBlock> = { 
        let mut block = EasyBlock::genesis();
        block.compute_hash();

        Arc::new(block) 
    };

    /// Canonical tips key
    static ref CANONICAL_TIPS_KEY: Hash = { crypto::hash_slice(b"canonical_tips") };
    
    /// Canonical tip block key
    static ref TIP_KEY: Hash = { crypto::hash_slice(b"canonical_tip") };

    /// Key to the hash of the canonical tip block in the hard chain.
    static ref HARD_TIP_KEY: Hash = { crypto::hash_slice(b"hard_canonical_tip") };

    /// The key to the canonical height of the chain
    static ref CANONICAL_HEIGHT_KEY: Hash = { crypto::hash_slice(b"canonical_height") };

    /// Key to the tip blocks in the chains that are
    /// disconnected from the canonical chain.
    static ref PENDING_TIPS_KEY: Hash = { crypto::hash_slice(b"pending_tips") };
}

#[derive(Clone)]
/// Thread-safe reference to an easy chain and its block cache.
pub struct EasyChainRef {
    /// Reference to easy chain.
    pub chain: Arc<RwLock<EasyChain>>,

    /// Block lookup cache.
    block_cache: Arc<Mutex<LruCache<Hash, Arc<EasyBlock>>>>
}

impl std::fmt::Debug for EasyChainRef {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "EasyChainRef {{ chain: {:?} }}", self.chain)
    }
}

impl EasyChainRef {
    pub fn new(chain: Arc<RwLock<EasyChain>>) -> EasyChainRef {
        EasyChainRef {
            chain,
            block_cache: Arc::new(Mutex::new(LruCache::new(BLOCK_CACHE_SIZE)))
        }
    }

    /// Attempts to fetch a block by its hash from the cache
    /// and if it doesn't succeed it then attempts to retrieve
    /// it from the database.
    pub fn query(&self, hash: &Hash) -> Option<Arc<EasyBlock>> {
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

#[derive(Debug)]
/// The easy chain stores blocks that represent buffered
/// validator pool join requests. If a miner wishes to become
/// a validator, it will most probably mine on the easy chain 
/// (which has lower difficulty in order to populate the pool
/// more effectively).
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
    height: u64,

    /// The tipmost block in the canonical chain.
    canonical_tip: Arc<EasyBlock>,

    /// The hash of the tip canonical block in the hard chain.
    hard_canonical_tip: Hash,

    /// Cache storing the tip blocks descended from the
    /// canonical chain and excluding the actual canonical
    /// tip block.
    canonical_tips_cache: HashSet<Arc<EasyBlock>>,

    /// Cache storing the tip blocks of chains that are
    /// disconnected from the canonical chain.
    pending_tips_cache: HashSet<Arc<EasyBlock>>,
}

impl EasyChain {
    pub fn new(mut db_ref: PersistentDb) -> EasyChain {
        let tip_db_res = db_ref.get(&TIP_KEY);
        let canonical_tip = match tip_db_res.clone() {
            Some(tip) => {
                let mut buf = [0; 32];
                buf.copy_from_slice(&tip);

                let block_bytes = db_ref.get(&Hash(buf)).unwrap();
                Arc::new(EasyBlock::from_bytes(&block_bytes).unwrap())
            }
            None => {
                EasyChain::genesis()
            }
        };

        let hard_canonical_tip = match db_ref.get(&HARD_TIP_KEY) {
            Some(hard_tip) => {
                let mut buf = [0; 32];
                buf.copy_from_slice(&hard_tip);

                Hash(buf)
            }
            None => {
                HardChain::genesis().block_hash().unwrap()
            }
        };

        // Insert new canonical tips entry if non-existent.
        let canonical_tips = match db_ref.get(&CANONICAL_TIPS_KEY) {
            Some(encoded) => {
                parse_encoded_blocks(&encoded)
            }
            None => {
                let b: Vec<Vec<u8>> = vec![canonical_tip.block_hash().unwrap().to_vec()];
                let encoded: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&b);

                db_ref.emplace(
                    CANONICAL_TIPS_KEY.clone(),
                    ElasticArray128::<u8>::from_slice(&encoded),
                );

                let mut b: HashSet<Arc<EasyBlock>> = HashSet::new();
                b.insert(canonical_tip.clone());

                b
            }
        };

        // Cache pending tips, if any
        let pending_tips = match db_ref.get(&PENDING_TIPS_KEY) {
            Some(encoded) => {
                parse_encoded_blocks(&encoded)
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

        EasyChain {
            canonical_tip,
            hard_canonical_tip,
            canonical_tips_cache: canonical_tips,
            pending_tips_cache: pending_tips,
            height,
            db: db_ref,
        }
    }

    /// Lists the given hash as the new canonical tip in the 
    /// hard chain. 
    /// 
    /// This can potentially change the canonical ordering in the 
    /// easy chain since they are cross-referenced and the ordering 
    /// on the easy chain is entirely dependent on the ordering of 
    /// the hard chain.
    pub fn set_hard_canonical_tip(&mut self, new: &Hash) -> Result<(), ()> {
        self.hard_canonical_tip = new.clone();
        Ok(())
    }
}

fn parse_encoded_blocks(bytes: &[u8]) -> HashSet<Arc<EasyBlock>> {
    let mut b = HashSet::new();
    let rlp = Rlp::new(bytes);

    for slice in rlp.iter() {
        b.insert(Arc::new(EasyBlock::from_bytes(slice.as_raw()).unwrap()));
    }

    b
}

impl Chain<EasyBlock> for EasyChain {
    fn genesis() -> Arc<EasyBlock> {
        GENESIS_RC.clone()
    }

    fn query(&self, hash: &Hash) -> Option<Arc<EasyBlock>> {
        if let Some(stored) = self.db.get(hash) {
            // Store to heap
            let heap_stored = Arc::new(EasyBlock::from_bytes(&stored).unwrap());
            Some(heap_stored)
        } else {
            None
        }
    }

    fn query_by_height(&self, height: u64) -> Option<Arc<EasyBlock>> {
        unimplemented!();
    }

    fn block_height(&self, hash: &Hash) -> Option<u64> {
        unimplemented!();
    }

    fn append_block(&mut self, block: Arc<EasyBlock>) -> Result<(), ChainErr> {
        let tip = &self.canonical_tip;

        // The block must have a parent hash and the parent
        // hash must be equal to that of the current tip
        // in order for it to be considered valid.
        if let Some(parent_hash) = block.parent_hash() {
            if parent_hash == tip.block_hash().unwrap() {
                // Place block in the ledger
                self.db.emplace(
                    block.block_hash().unwrap().clone(),
                    ElasticArray128::<u8>::from_slice(&block.to_bytes()),
                );

                // Set new canonical tip block
                self.canonical_tip = block;

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

                Ok(())
            } else {
                Err(ChainErr::InvalidParent)
            }
        } else {
            Err(ChainErr::NoParentHash)
        }
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn canonical_tip(&self) -> Arc<EasyBlock> {
        self.canonical_tip.clone()
    }
}
