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
use crate::validation_status::ValidationStatus;
use bin_tools::*;
use crypto::Hash;
use elastic_array::ElasticArray128;
use hashbrown::{HashSet, HashMap};
use hashdb::HashDB;
use lru::LruCache;
use parking_lot::{RwLock, Mutex};
use persistence::PersistentDb;
use std::sync::Arc;
use lazy_static::*;

/// Size of the block cache.
const BLOCK_CACHE_SIZE: usize = 20;

/// Maximum orphans allowed.
const MAX_ORPHANS: usize = 100;

/// Blocks with height below the canonical height minus 
/// this number will be rejected.
const MIN_HEIGHT: u64 = 10;

/// Blocks with height below the canonical height minus
/// this number will be rejected.
const MAX_HEIGHT: u64 = 10;

lazy_static! {
    /// Atomic reference count to hard chain genesis block
    static ref GENESIS_RC: Arc<HardBlock> = { 
        let mut block = HardBlock::genesis();
        block.compute_hash();

        Arc::new(block) 
    };
    
    /// Canonical tip block key
    static ref TIP_KEY: Hash = { crypto::hash_slice(b"canonical_tip") };

    /// The key to the canonical height of the chain
    static ref CANONICAL_HEIGHT_KEY: Hash = { crypto::hash_slice(b"canonical_height") };
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

#[derive(Debug)]
/// The hard chain stores blocks that represent state 
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

    /// Memory pool of blocks that are not in the canonical chain.
    orphan_pool: HashMap<Hash, Arc<HardBlock>>,

    /// The biggest height of all orphans
    max_orphan_height: Option<u64>,

    /// Mapping between heights and their sets of
    /// orphans mapped to their inverse height.
    heights_mapping: HashMap<u64, HashMap<Hash, Option<u64>>>,

    /// Mapping between orphans and their validation statuses.
    validations_mapping: HashMap<Hash, ValidationStatus>,

    /// Mapping between disconnected chains heads and tips.
    disconnected_heads_mapping: HashMap<Hash, HashSet<Hash>>,

    /// Mapping between disconnected chains tips and heads.
    disconnected_tips_mapping: HashMap<Hash, Hash>,
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
            orphan_pool: HashMap::with_capacity(MAX_ORPHANS),
            heights_mapping: HashMap::with_capacity(MAX_ORPHANS),
            validations_mapping: HashMap::with_capacity(MAX_ORPHANS),
            disconnected_heads_mapping: HashMap::with_capacity(MAX_ORPHANS),
            disconnected_tips_mapping: HashMap::with_capacity(MAX_ORPHANS),
            max_orphan_height: None,
            height,
            easy_chain,
            db: db_ref,
        }
    }

    // TODO: Make writes atomic
    fn write_block(&mut self, block: Arc<HardBlock>) {
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

        // Remove block from orphan pool
        self.orphan_pool.remove(&block_hash);

        // Remove from height mappings
        if let Some(orphans) = self.heights_mapping.get_mut(&block.height()) {
            orphans.remove(&block_hash);
        }

        // Remove from validations mapping
        self.validations_mapping.remove(&block_hash);

        // Mark new hard chain tip block in easy chain
        let mut easy_chain = self.easy_chain.chain.write();
        easy_chain.set_hard_canonical_tip(&block.block_hash().unwrap()).unwrap();
    }

    fn write_orphan(
        &mut self, 
        orphan: Arc<HardBlock>, 
        validation_status: ValidationStatus,
        inverse_height: Option<u64>,
    ) {
        let orphan_hash = orphan.block_hash().unwrap();
        let height = orphan.height();

        // Write height mapping
        if let Some(height_entry) = self.heights_mapping.get_mut(&height) {
            height_entry.insert(orphan_hash.clone(), inverse_height);
        } else {
            let mut map = HashMap::new();
            map.insert(orphan_hash.clone(), inverse_height);

            self.heights_mapping.insert(height, map);
        }

        // Write to orphan pool
        self.orphan_pool.insert(orphan_hash.clone(), orphan.clone());

        // Set max orphan height if this is the case
        if let Some(max_orphan_height) = self.max_orphan_height {
            if height > max_orphan_height {
                self.max_orphan_height = Some(height);
            }
        } else {
            self.max_orphan_height = Some(height);
        }

        // Write to validations mappings
        self.validations_mapping.insert(orphan_hash, validation_status);
    }

    /// Attempts to attach orphans to the canonical chain
    /// starting with the given height.
    fn process_orphans(&mut self, start_height: u64) {
        if let Some(max_orphan_height) = self.max_orphan_height {
            let mut h = start_height;
            
            loop {
                if h > max_orphan_height {
                    break;
                }

                if let Some(orphans) = self.heights_mapping.get(&h) {
                    if orphans.len() == 1 {
                        // HACK: Maybe we can find a better/faster way to get the only item of a set?
                        let (orphan_hash, _) = orphans.iter().find(|_| true).unwrap();
                        let orphan = self.orphan_pool.get(orphan_hash).unwrap();

                        // If the orphan directly follows the canonical
                        // tip, write it to the chain.
                        if orphan.parent_hash().unwrap() == self.canonical_tip().block_hash().unwrap() {
                            self.write_block(orphan.clone());
                        }
                    } else if orphans.is_empty() {
                        break;
                    } else {
                        let mut orphans: Vec<(Hash, Option<u64>)> = orphans
                            .iter()
                            .filter(|(o, i_h)| {
                                // Filter out orphans that do not follow
                                // the canonical tip or which do not have
                                // an inverse height.
                                let orphan = self.orphan_pool.get(o).unwrap();

                                let orphan_parent = orphan.parent_hash().unwrap();
                                let canonical_parent = self.canonical_tip().parent_hash().unwrap();
                                
                                orphan_parent == canonical_parent && i_h.is_some()
                            })
                            .map(|(o, i_h)| (o.clone(), i_h.clone()))
                            .collect();
                        
                        // Write the orphan with the greatest inverse height
                        orphans.sort_unstable_by(|(_, a), (_, b)| a.unwrap().cmp(&b.unwrap()));

                        if let Some((to_write, _)) = orphans.pop() {
                            let to_write = self.orphan_pool.get(&to_write).unwrap();

                            self.write_block(to_write.clone());
                        }
                    }
                }

                h += 1;
            }
        }
    }

    /// Attempts to switch the canonical chain to the valid chain
    /// which has the given canidate tip. Do nothing if this is not
    /// possible.
    fn attempt_switch(&mut self, candidate_tip: Arc<HardBlock>) {
        // TODO: Possibly add an offset here so we don't switch
        // chains that often on many chains competing for being
        // canonical.
        if candidate_tip.height() > self.height {
            unimplemented!();
        }
    }

    /// Attempts to attach a disconnected chain tip to other
    /// disconnected chains. Returns the final status of the tip.
    fn attempt_attach(&mut self, tip_hash: &Hash, initial_status: ValidationStatus) -> ValidationStatus {
        let mut status = initial_status;
        let mut to_attach = Vec::with_capacity(MAX_ORPHANS);

        for (head_hash, _) in self.disconnected_heads_mapping.iter() {
            // Skip our tip
            if let Some(tips) = self.disconnected_heads_mapping.get(head_hash) {
                if tips.contains(tip_hash) {
                    continue;
                }
            } 

            let head = self.orphan_pool.get(head_hash).unwrap();
        
            // Attach chain to our tip
            if head.parent_hash().unwrap() == *tip_hash {
                to_attach.push(head_hash.clone());
                status = ValidationStatus::BelongsToDisconnected;
            }
        }

        let cur_head = if let ValidationStatus::Unknown = initial_status {
            tip_hash.clone()  
        } else {
            self.disconnected_tips_mapping.get(tip_hash).unwrap().clone()
        };

        // Attach heads
        for head in to_attach.iter() {
            let tips = self.disconnected_heads_mapping.remove(head).unwrap();
            
            if let Some(cur_tips) = self.disconnected_heads_mapping.get_mut(&cur_head) {
                // Merge tips
                for tip in tips.iter() {
                    if let Some(head_mapping) = self.disconnected_tips_mapping.get_mut(tip) {
                        *head_mapping = cur_head.clone();
                    } else {
                        self.disconnected_tips_mapping.insert(tip.clone(), cur_head.clone());
                    }
                    
                    cur_tips.insert(tip.clone());
                }
            }
        }

        status
    }

    /// Attempts to attach a canonical chain tip to other
    /// disconnected chains. Returns the final status of the 
    /// old tip, its inverse height and the new tip.
    fn attempt_attach_valid(&mut self, tip_hash: &Hash) -> (ValidationStatus, u64, Arc<HardBlock>) {
        unimplemented!();
    }

    /// Recurses the parents of the orphan and updates their
    /// inverse heights according to the provided start height 
    /// of the orphan.
    fn recurse_inverse(&mut self, orphan: Arc<HardBlock>, start_height: u64) {
        let mut cur_inverse = start_height;
        let mut current = orphan;

        // Recurse parents and update inverse height
        // until we reach a missing block or the 
        // canonical chain.
        while let Some(parent) = self.orphan_pool.get(&current.parent_hash().unwrap()) {
            let par_height = parent.height();
            let orphans = self.heights_mapping.get_mut(&par_height).unwrap();
            let inverse_h_entry = orphans.get_mut(&parent.block_hash().unwrap()).unwrap();

            if let Some(entry) = inverse_h_entry {
                if *entry < cur_inverse + 1 {
                    *entry = cur_inverse + 1;
                }
            } else {
                *inverse_h_entry = Some(cur_inverse + 1);
            }

            current = parent.clone();
            cur_inverse += 1;
        }
    }
}

impl Chain<HardBlock> for HardChain {
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

        let block_hash = block.block_hash().unwrap();

        // Check for existence
        if self.orphan_pool.get(&block_hash).is_some() || self.db.get(&block_hash).is_some() {
            return Err(ChainErr::AlreadyInChain);
        }

        let tip = &self.canonical_tip;

        if let Some(parent_hash) = block.parent_hash() {
            // First attempt to place the block after the 
            // tip canonical block.
            if parent_hash == tip.block_hash().unwrap() {
                // The height must be equal to that of the parent plus one
                if block.height() != self.height + 1 {
                    return Err(ChainErr::BadHeight);
                }

                let height = block.height();

                // Write block to the chain
                self.write_block(block);

                // Process orphans
                self.process_orphans(height);

                Ok(())
            } else {
                // If the parent exists and it is not the canonical
                // tip this means that this block is represents a 
                // potential fork in the chain so we add it to the
                // orphan pool.
                match self.db.get(&parent_hash) {
                    Some(parent_block) => {
                        let height = block.height();
                        let parent_height = HardBlock::from_bytes(&parent_block).unwrap().height();

                        // The height must be equal to that of the parent plus one
                        if height != parent_height + 1 {
                            return Err(ChainErr::BadHeight);
                        }

                        let (status, inverse_height, tip) = self.attempt_attach_valid(&block_hash);
                        self.write_orphan(block, status, Some(inverse_height));
                        self.attempt_switch(tip);

                        Ok(())
                    }
                    None => {
                        // The parent is an orphan
                        if let Some(parent_block) = self.orphan_pool.get(&parent_hash) {
                            let height = block.height();

                            // The height must be equal to that of the parent plus one
                            if height != parent_block.height() + 1 {
                                return Err(ChainErr::BadHeight);
                            }

                            let parent_status = self.validations_mapping.get_mut(&parent_hash).unwrap();

                            match parent_status {
                                ValidationStatus::Unknown => {
                                    // Change status of old tip
                                    *parent_status = ValidationStatus::BelongsToDisconnected;

                                    let mut set = HashSet::new();
                                    set.insert(block_hash.clone());

                                    // Add to disconnected mappings
                                    self.disconnected_heads_mapping.insert(parent_hash.clone(), set);
                                    self.disconnected_tips_mapping.insert(block_hash.clone(), parent_hash.clone());

                                    let status = self.attempt_attach(&block_hash, ValidationStatus::DisconnectedTip);
                                    
                                    if let ValidationStatus::DisconnectedTip = status {
                                        self.disconnected_tips_mapping.insert(block_hash.clone(), parent_hash.clone());
                                    }

                                    self.write_orphan(block, status, None);
                                }
                                ValidationStatus::DisconnectedTip => {
                                    let head = self.disconnected_tips_mapping.get(&parent_hash).unwrap().clone();
                                    let tips = self.disconnected_heads_mapping.get_mut(&head).unwrap();

                                    // Change status of old tip
                                    *parent_status = ValidationStatus::BelongsToDisconnected;

                                    // Replace old tip in mappings
                                    tips.remove(&parent_hash);
                                    tips.insert(block_hash.clone());

                                    self.disconnected_tips_mapping.insert(block_hash.clone(), head);
                                    let status = self.attempt_attach(&block_hash, ValidationStatus::DisconnectedTip);

                                    self.disconnected_tips_mapping.remove(&parent_hash);
                                    self.write_orphan(block, status, None);
                                }
                                ValidationStatus::ValidChainTip => {
                                    // Change status of old tip
                                    *parent_status = ValidationStatus::BelongsToValidChain;

                                    let (status, inverse_height, tip) = self.attempt_attach_valid(&block_hash);

                                    // Mark orphan as the new tip
                                    self.write_orphan(block.clone(), status, Some(inverse_height));

                                    // Recurse parents and modify their inverse heights
                                    self.recurse_inverse(tip.clone(), inverse_height);

                                    // Check if the new tip's height is greater than
                                    // the canonical chain, and if so, switch chains.
                                    self.attempt_switch(tip);
                                }
                                ValidationStatus::BelongsToDisconnected => {
                                    let head = { 
                                        // Recurse parents until we find the head block
                                        let mut current = parent_hash.clone();
                                        let mut result = None;

                                        loop {
                                            if self.disconnected_heads_mapping.get(&current).is_some() {
                                                result = Some(current);
                                                break;
                                            } 

                                            if let Some(orphan) = self.orphan_pool.get(&current) {
                                                current = orphan.parent_hash().unwrap();
                                            } else {
                                                unreachable!();
                                            }
                                        }

                                        result.unwrap()
                                    };

                                    // Add to disconnected mappings
                                    self.disconnected_tips_mapping.insert(block_hash.clone(), head.clone());
                                    
                                    let status = self.attempt_attach(&block_hash, ValidationStatus::DisconnectedTip);

                                    if let ValidationStatus::DisconnectedTip = status {
                                        self.disconnected_tips_mapping.insert(block_hash.clone(), head);
                                    }

                                    self.write_orphan(block, status, None);
                                }
                                ValidationStatus::BelongsToValidChain => {
                                    let (status, inverse_height, tip) = self.attempt_attach_valid(&block_hash);

                                    self.write_orphan(block, status, Some(inverse_height));
                                    self.recurse_inverse(tip.clone(), inverse_height);
                                    self.attempt_switch(tip);
                                }
                            }

                            Ok(())
                        } else {
                            let status = self.attempt_attach(&block_hash, ValidationStatus::Unknown);
                            self.write_orphan(block, status, None);
                            Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::easy_chain::chain::EasyChain;
    use rand::*;
    use quickcheck::*;

    quickcheck! {
        /// Stress test of chain append.
        /// 
        /// We have blocks of the following structure:
        /// ```
        /// GEN -> A -> B -> C -> D -> E -> F -> G
        ///        |
        ///         -> B' -> C' -> D' -> E'
        ///            |     |
        ///            |     -> D'''
        ///            |
        ///            -> C'' -> D'' -> E'' -> F''
        /// ```
        /// 
        /// The tip of the block must always be `G`, regardless
        /// of the order in which the blocks are received. And 
        /// the height of the chain must be that of `G` which is 7.
        fn append_stress_test() -> bool {
            let db = test_helpers::init_tempdb();
            let easy_chain = Arc::new(RwLock::new(EasyChain::new(db.clone())));
            let easy_ref = EasyChainRef::new(easy_chain);
            let mut hard_chain = HardChain::new(db, easy_ref);

            let mut A = HardBlock::new(Some(HardChain::genesis().block_hash().unwrap()), 1, EasyChain::genesis().block_hash().unwrap());
            A.calculate_merkle_root();
            A.compute_hash();
            let A = Arc::new(A);

            let mut B = HardBlock::new(Some(A.block_hash().unwrap()), 2, EasyChain::genesis().block_hash().unwrap());
            B.calculate_merkle_root();
            B.compute_hash();
            let B = Arc::new(B);

            let mut C = HardBlock::new(Some(B.block_hash().unwrap()), 3, EasyChain::genesis().block_hash().unwrap());
            C.calculate_merkle_root();
            C.compute_hash();
            let C = Arc::new(C);

            let mut D = HardBlock::new(Some(C.block_hash().unwrap()), 4, EasyChain::genesis().block_hash().unwrap());
            D.calculate_merkle_root();
            D.compute_hash();
            let D = Arc::new(D);

            let mut E = HardBlock::new(Some(D.block_hash().unwrap()), 5, EasyChain::genesis().block_hash().unwrap());
            E.calculate_merkle_root();
            E.compute_hash();
            let E = Arc::new(E);

            let mut F = HardBlock::new(Some(E.block_hash().unwrap()), 6, EasyChain::genesis().block_hash().unwrap());
            F.calculate_merkle_root();
            F.compute_hash();
            let F = Arc::new(F);

            let mut G = HardBlock::new(Some(F.block_hash().unwrap()), 7, EasyChain::genesis().block_hash().unwrap());
            G.calculate_merkle_root();
            G.compute_hash();
            let G = Arc::new(G);

            let mut B_prime = HardBlock::new(Some(A.block_hash().unwrap()), 2, EasyChain::genesis().block_hash().unwrap());
            B_prime.calculate_merkle_root();
            B_prime.compute_hash();
            let B_prime = Arc::new(B_prime);

            let mut C_prime = HardBlock::new(Some(B_prime.block_hash().unwrap()), 3, EasyChain::genesis().block_hash().unwrap());
            C_prime.calculate_merkle_root();
            C_prime.compute_hash();
            let C_prime = Arc::new(C_prime);

            let mut D_prime = HardBlock::new(Some(C_prime.block_hash().unwrap()), 4, EasyChain::genesis().block_hash().unwrap());
            D_prime.calculate_merkle_root();
            D_prime.compute_hash();
            let D_prime = Arc::new(D_prime);

            let mut E_prime = HardBlock::new(Some(D_prime.block_hash().unwrap()), 5, EasyChain::genesis().block_hash().unwrap());
            E_prime.calculate_merkle_root();
            E_prime.compute_hash();
            let E_prime = Arc::new(E_prime);

            let mut C_second = HardBlock::new(Some(B_prime.block_hash().unwrap()), 3, EasyChain::genesis().block_hash().unwrap());
            C_second.calculate_merkle_root();
            C_second.compute_hash();
            let C_second = Arc::new(C_second);

            let mut D_second = HardBlock::new(Some(C_second.block_hash().unwrap()), 4, EasyChain::genesis().block_hash().unwrap());
            D_second.calculate_merkle_root();
            D_second.compute_hash();
            let D_second = Arc::new(D_second);

            let mut E_second = HardBlock::new(Some(D_second.block_hash().unwrap()), 5, EasyChain::genesis().block_hash().unwrap());
            E_second.calculate_merkle_root();
            E_second.compute_hash();
            let E_second = Arc::new(E_second);

            let mut F_second = HardBlock::new(Some(E_second.block_hash().unwrap()), 6, EasyChain::genesis().block_hash().unwrap());
            F_second.calculate_merkle_root();
            F_second.compute_hash();
            let F_second = Arc::new(F_second);

            let mut D_tertiary = HardBlock::new(Some(C_prime.block_hash().unwrap()), 4, EasyChain::genesis().block_hash().unwrap());
            D_tertiary.calculate_merkle_root();
            D_tertiary.compute_hash();
            let D_tertiary = Arc::new(D_tertiary);

            let mut blocks = vec![
                A,
                B,
                C,
                D,
                E,
                F,
                G.clone(),
                B_prime,
                C_prime,
                D_prime,
                E_prime,
                C_second,
                D_second,
                E_second,
                F_second,
                D_tertiary
            ];

            // Shuffle blocks
            thread_rng().shuffle(&mut blocks);

            for b in blocks {
                hard_chain.append_block(b).unwrap();
            }

            assert_eq!(hard_chain.height(), 7);
            assert_eq!(hard_chain.canonical_tip(), G);

            true
        }
    }
}