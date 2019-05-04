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
use std::collections::VecDeque;
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
    heights_mapping: HashMap<u64, HashMap<Hash, u64>>,

    /// Mapping between orphans and their validation statuses.
    validations_mapping: HashMap<Hash, ValidationStatus>,

    /// Mapping between disconnected chains heads and tips.
    disconnected_heads_mapping: HashMap<Hash, HashSet<Hash>>,

    /// Mapping between disconnected heads and the largest 
    /// height of any associated tip along with its hash.
    disconnected_heads_heights: HashMap<Hash, (u64, Hash)>,

    /// Mapping between disconnected chains tips and heads.
    disconnected_tips_mapping: HashMap<Hash, Hash>,

    /// Set containing tips of valid chains that descend
    /// from the canonical chain.
    valid_tips: HashSet<Hash>,
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
            disconnected_heads_heights: HashMap::with_capacity(MAX_ORPHANS),
            disconnected_tips_mapping: HashMap::with_capacity(MAX_ORPHANS),
            valid_tips: HashSet::with_capacity(MAX_ORPHANS),
            max_orphan_height: None,
            height,
            easy_chain,
            db: db_ref,
        }
    }

    /// Rewinds the canonical chain to the block with the given hash.
    /// 
    /// Returns `Err(ChainErr::NoSuchBlock)` if there is no block with
    /// the given hash in the canonical chain.
    pub fn rewind(&mut self, block_hash: &Hash) -> Result<(), ChainErr> {
        if *block_hash == HardChain::genesis().block_hash().unwrap() {
            unimplemented!();
        }

        if let Some(new_tip) = self.db.get(block_hash) {
            let new_tip = Arc::new(HardBlock::from_bytes(&new_tip).unwrap());

            // TODO: Make writes and deletes atomic
            let mut current = self.canonical_tip.clone();
            let mut inverse_height = 1;

            // Remove canonical tip from the chain 
            // and mark it as a valid chain tip.
            self.db.remove(&current.block_hash().unwrap());

            // Add the old tip to the orphan pool
            self.orphan_pool.insert(current.block_hash().unwrap(), current.clone());

            // Mark old tip as a valid chain tip
            self.validations_mapping.insert(current.block_hash().unwrap(), ValidationStatus::ValidChainTip);
            self.valid_tips.insert(current.block_hash().unwrap());

            let cur_height = current.height();

            // Insert to heights mapping
            if let Some(entries) = self.heights_mapping.get_mut(&cur_height) {
                entries.insert(current.block_hash().unwrap(), 0);
            } else {
                let mut hm = HashMap::new();
                hm.insert(current.block_hash().unwrap(), 0);
                self.heights_mapping.insert(cur_height, hm);
            }

            // Recurse parents and remove them until we
            // reach the block with the given hash.
            loop {
                let parent_hash = current.parent_hash().unwrap();

                if parent_hash == *block_hash {
                    break;
                } else {
                    let parent = Arc::new(HardBlock::from_bytes(&self.db.get(&parent_hash).unwrap()).unwrap());
                    let cur_height = parent.height();

                    // Remove parent from db
                    self.db.remove(&parent_hash);

                    // Add the parent to the orphan pool
                    self.orphan_pool.insert(parent.block_hash().unwrap(), parent.clone());

                    // Mark parent as belonging to a valid chain
                    self.validations_mapping.insert(parent.block_hash().unwrap(), ValidationStatus::BelongsToValidChain);

                    // Insert to heights mapping
                    if let Some(entries) = self.heights_mapping.get_mut(&cur_height) {
                        entries.insert(parent.block_hash().unwrap(), inverse_height);
                    } else {
                        let mut hm = HashMap::new();
                        hm.insert(parent.block_hash().unwrap(), inverse_height);
                        self.heights_mapping.insert(cur_height, hm);
                    }

                    current = parent;
                    inverse_height += 1;
                }
            }
            
            self.height = new_tip.height();
            self.write_canonical_height(new_tip.height());
            self.canonical_tip = new_tip;

            Ok(())
        } else {
            Err(ChainErr::NoSuchBlock)
        }
    }

    // TODO: Make writes atomic
    fn write_block(&mut self, block: Arc<HardBlock>) {
        let block_hash = block.block_hash().unwrap();

        // We can only write a block whose parent
        // hash is the hash of the current canonical
        // tip block. 
        assert_eq!(block.parent_hash().unwrap(), self.canonical_tip.block_hash().unwrap());

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

        let encoded_height = encode_be_u64!(height);

        // Write new height
        self.write_canonical_height(height);

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

        // Remove from valid tips
        self.valid_tips.remove(&block_hash);

        // Remove from disconnected mappings
        let tips = self.disconnected_heads_mapping.remove(&block_hash);
        self.disconnected_heads_heights.remove(&block_hash);
        self.disconnected_tips_mapping.remove(&block_hash);

        // If the block is a head block, mark the associated
        // chains as valid chains.
        if let Some(tips) = tips {
            // For each tip, find their head hash
            for tip_hash in tips.iter() {
                // Skip written block
                if *tip_hash == block_hash {
                    continue;
                }

                let tip = self.orphan_pool.get(tip_hash).unwrap();
                let mut current = tip.parent_hash().unwrap();

                // Mark as valid chain tip
                self.valid_tips.insert(tip_hash.clone());

                // Mark as valid chain tip in validations mapping
                let status = self.validations_mapping.get_mut(tip_hash).unwrap();
                *status = ValidationStatus::ValidChainTip;

                // Loop parents until we can't find one 
                while let Some(parent) = self.orphan_pool.get(&current) {
                    // Mark as belonging to valid chain
                    let status = self.validations_mapping.get_mut(&parent.block_hash().unwrap()).unwrap();
                    *status = ValidationStatus::BelongsToValidChain;

                    current = parent.parent_hash().unwrap();
                }
                
                // Remove from disconnected mappings
                self.disconnected_tips_mapping.remove(&tip_hash.clone());
            }
        }

        // Mark new hard chain tip block in easy chain
        let mut easy_chain = self.easy_chain.chain.write();
        easy_chain.set_hard_canonical_tip(&block.block_hash().unwrap()).unwrap();
    }

    fn write_canonical_height(&mut self, height: u64) {
        let encoded_height = encode_be_u64!(height);
        self.db.emplace(
            CANONICAL_HEIGHT_KEY.clone(),
            ElasticArray128::<u8>::from_slice(&encoded_height),
        );
    }

    fn write_orphan(
        &mut self, 
        orphan: Arc<HardBlock>, 
        validation_status: ValidationStatus,
        inverse_height: u64,
    ) {
        let orphan_hash = orphan.block_hash().unwrap();
        let height = orphan.height();

        match validation_status {
            ValidationStatus::ValidChainTip => {
                self.valid_tips.insert(orphan.block_hash().unwrap());
            }
            _ => {
                // Do nothing
            }
        }

        // Write height mapping
        if let Some(height_entry) = self.heights_mapping.get_mut(&height) {
            if height_entry.get(&orphan_hash).is_none() {
                height_entry.insert(orphan_hash.clone(), inverse_height);
            }
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
            let mut done = false;
            let mut prev_valid_tips = HashSet::new();
            
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
                        if orphan.parent_hash().unwrap() == self.canonical_tip.block_hash().unwrap() {
                            if !done {
                                self.write_block(orphan.clone());
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    } else if orphans.is_empty() {
                        if prev_valid_tips.is_empty() {
                            break;
                        } else {
                            // Mark processing as done but continue so we can
                            // update the current valid chains.
                            if !done {
                                done = true;
                            } else {
                                break;
                            }
                        }
                    } else {
                        let mut buf: Vec<(Hash, u64)> = Vec::with_capacity(orphans.len());
                        
                        for (o, i_h) in orphans.iter() {
                            // Filter out orphans that do not follow
                            // the canonical tip.
                            let orphan = self.orphan_pool.get(o).unwrap();
                            let orphan_parent = orphan.parent_hash().unwrap();
                            let canonical_tip = self.canonical_tip.block_hash().unwrap();
                            
                            if orphan_parent == canonical_tip {
                                buf.push((o.clone(), i_h.clone()));
                            } else if prev_valid_tips.contains(&orphan_parent) {
                                // Mark old tip as belonging to valid chain
                                let parent_status = self.validations_mapping.get_mut(&orphan_parent).unwrap();
                                *parent_status = ValidationStatus::BelongsToValidChain;

                                // Mark new tip
                                let status = self.validations_mapping.get_mut(&o).unwrap();
                                *status = ValidationStatus::ValidChainTip;

                                // Add to valid tips sets
                                self.valid_tips.remove(&orphan_parent);
                                self.valid_tips.insert(o.clone());
                                prev_valid_tips.remove(&orphan_parent);
                                prev_valid_tips.insert(o.clone());
                            }
                        }

                        if buf.is_empty() {
                            if prev_valid_tips.is_empty() {
                                break;
                            } else {
                                // Mark processing as done but continue so we can
                                // update tips information.
                                if !done {
                                    done = true;
                                    continue;
                                } else {
                                    break;
                                }
                            }
                        }
                        
                        // Write the orphan with the greatest inverse height
                        buf.sort_unstable_by(|(_, a), (_, b)| a.cmp(&b));

                        if !done {
                            if let Some((to_write, _)) = buf.pop() {
                                let to_write = self.orphan_pool.get(&to_write).unwrap();
                                self.write_block(to_write.clone());
                            }
                        }

                        // Place remaining tips in valid tips set 
                        // and mark them as valid chain tips.
                        for (o, _) in buf {
                            let status = self.validations_mapping.get_mut(&o).unwrap();
                            *status = ValidationStatus::ValidChainTip;
                            prev_valid_tips.insert(o);
                            self.valid_tips.insert(o.clone());
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
        assert!(self.valid_tips.contains(&candidate_tip.block_hash().unwrap()));

        // TODO: Possibly add an offset here so we don't switch
        // chains that often on many chains competing for being
        // canonical.
        if candidate_tip.height() > self.height {
            let mut to_write: VecDeque<Arc<HardBlock>> = VecDeque::new();
            to_write.push_front(candidate_tip.clone());

            // Find the horizon block i.e. the common
            // ancestor of both the candidate tip and 
            // the canonical tip.
            let horizon = {
                let mut current = candidate_tip.parent_hash().unwrap();

                // Recurse parents until we find a canonical block
                loop {
                    if self.db.get(&current).is_some() {
                        break;
                    } 

                    let cur = self.orphan_pool.get(&current).unwrap();
                    to_write.push_front(cur.clone());

                    current = cur.parent_hash().unwrap();
                }

                current
            };
            
            // Rewind to horizon
            self.rewind(&horizon).unwrap();

            // Write the blocks from the candidate chain
            for block in to_write {
                // Don't write the horizon
                if block.block_hash().unwrap() == horizon {
                    continue;
                }

                self.write_block(block);
            }
        }
    }

    /// Attempts to attach a disconnected chain tip to other
    /// disconnected chains. Returns the final status of the tip.
    fn attempt_attach(&mut self, tip_hash: &Hash, initial_status: ValidationStatus) -> ValidationStatus {
        let mut status = initial_status;
        let mut to_attach = Vec::with_capacity(MAX_ORPHANS);
        let our_head_hash = self.disconnected_tips_mapping.get(tip_hash).unwrap();

        // Find a matching disconnected chain head
        for (head_hash, _) in self.disconnected_heads_mapping.iter() {
            // Skip our tip
            if head_hash == our_head_hash || head_hash == tip_hash {
                continue;
            } 

            let head = self.orphan_pool.get(head_hash).unwrap();
        
            // Attach chain to our tip
            if head.parent_hash().unwrap() == *tip_hash {
                to_attach.push(head_hash.clone());
                status = ValidationStatus::BelongsToDisconnected;
            }
        }

        let cur_head = self.disconnected_tips_mapping.get(tip_hash).unwrap().clone();

        // Attach heads
        for head in to_attach.iter() {
            let tips = self.disconnected_heads_mapping.remove(head).unwrap();
            self.disconnected_heads_heights.remove(head).unwrap();
            
            if let Some(cur_tips) = self.disconnected_heads_mapping.get_mut(&cur_head) {
                let mut to_recurse = Vec::with_capacity(tips.len());

                // Merge tips
                for tip_hash in tips.iter() {
                    let tip = self.orphan_pool.get(tip_hash).unwrap();
                    let (largest_height, _) = self.disconnected_heads_heights.get(&cur_head).unwrap();

                    if let Some(head_mapping) = self.disconnected_tips_mapping.get_mut(tip_hash) {
                        *head_mapping = cur_head.clone();
                    } else {
                        self.disconnected_tips_mapping.insert(tip_hash.clone(), cur_head.clone());
                    }

                    // Update heights entry if new tip height is larger
                    if tip.height() > *largest_height {
                        self.disconnected_heads_heights.insert(cur_head.clone(), (tip.height(), tip.block_hash().unwrap()));
                    }
                    
                    to_recurse.push(tip.clone());
                    cur_tips.insert(tip_hash.clone());
                }

                // Update inverse heights starting from pushed tips
                for tip in to_recurse {
                    self.recurse_inverse(tip, 0, false);
                }
            }
        }

        status
    }

    /// Attempts to attach a canonical chain tip to other
    /// disconnected chains. Returns the final status of the 
    /// old tip, its inverse height and the new tip.
    fn attempt_attach_valid(
        &mut self, 
        tip: &mut Arc<HardBlock>, 
        inverse_height: &mut u64, 
        status: &mut ValidationStatus
    ) {
        assert!(self.valid_tips.contains(&tip.block_hash().unwrap()));

        let iterable = self.disconnected_heads_heights
            .iter()
            .filter(|(h, (_, largest_tip))| {
                let tips = self.disconnected_heads_mapping.get(h).unwrap();
                assert!(tips.contains(&largest_tip));

                let head = self.orphan_pool.get(h).unwrap();
                let parent_hash = head.parent_hash().unwrap();

                parent_hash == tip.block_hash().unwrap()
            });

        let mut current = None;
        let mut current_height = (0, None);

        // Find the head that follows our tip that 
        // has the largest potential height.
        for (head_hash, (largest_height, largest_tip)) in iterable {
            let (cur_height, _) = current_height;

            if current.is_none() || *largest_height > cur_height {
                current = Some(head_hash);
                current_height = (*largest_height, Some(largest_tip));
            }
        }

        // If we have a matching chain, update the return values.
        if let Some(head_hash) = current {
            let (largest_height, largest_tip) = current_height;
            let largest_tip = self.orphan_pool.get(&largest_tip.unwrap()).unwrap().clone();
            let tip_height = tip.height();

            *status = ValidationStatus::BelongsToValidChain;
            *inverse_height = largest_height - tip_height;
            *tip = largest_tip;
        
            self.make_valid_tips(&head_hash.clone());
        }

        // Update inverse heights
        self.recurse_inverse(tip.clone(), 0, true);
    }

    /// Recursively changes the validation status of the tips
    /// of the given head to `ValidationStatus::ValidChainTip` 
    /// and of their parents to `ValidationStatus::BelongsToValid`. 
    /// 
    /// Also removes all the disconnected mappings related to the head. 
    fn make_valid_tips(&mut self, head: &Hash) {
        let tips = self.disconnected_heads_mapping.remove(head).unwrap();
        self.disconnected_heads_heights.remove(head);

        for tip_hash in tips.iter() {
            let tip = self.orphan_pool.get(tip_hash).unwrap();

            // Update status
            let status = self.validations_mapping.get_mut(tip_hash).unwrap();
            *status = ValidationStatus::ValidChainTip;
            
            // Update mappings
            self.disconnected_tips_mapping.remove(tip_hash);
            self.valid_tips.insert(tip_hash.clone());

            let mut current = tip.parent_hash().unwrap();
            
            // For each tip, recurse parents and update their
            // validation status until we either find a parent
            // with the good status or until we reach the 
            // canonical chain.
            loop {
                if let Some(parent) = self.orphan_pool.get(&current) {
                    let status = self.validations_mapping.get_mut(&parent.block_hash().unwrap()).unwrap();
                    
                    // Don't continue if we have already been here
                    if let ValidationStatus::BelongsToValidChain = status {
                        break;
                    }

                    *status = ValidationStatus::BelongsToValidChain;
                    current = parent.parent_hash().unwrap();
                } else {
                    break;
                }
            }
        }
    }

    /// Recurses the parents of the orphan and updates their
    /// inverse heights according to the provided start height 
    /// of the orphan. The third argument specifies if we should
    /// mark the recursed chain as a valid canonical chain.
    fn recurse_inverse(&mut self, orphan: Arc<HardBlock>, start_height: u64, make_valid: bool) {
        let mut cur_inverse = start_height;
        let mut current = orphan.clone();
        
        // This flag only makes sense when the 
        // starting inverse height is 0.
        if make_valid {
            assert_eq!(start_height, 0);

            // Mark orphan as being tip of a valid chain
            let key = orphan.block_hash().unwrap();

            if let Some(validation) = self.validations_mapping.get_mut(&key) {
                *validation = ValidationStatus::ValidChainTip;
            } else {
                self.validations_mapping.insert(key, ValidationStatus::ValidChainTip);
            }
        }

        // Recurse parents and update inverse height
        // until we reach a missing block or the 
        // canonical chain.
        while let Some(parent) = self.orphan_pool.get(&current.parent_hash().unwrap()) {
            let par_height = parent.height();
            let orphans = self.heights_mapping.get_mut(&par_height).unwrap();
            let inverse_h_entry = orphans.get_mut(&parent.block_hash().unwrap()).unwrap();

            if *inverse_h_entry < cur_inverse + 1 {
                *inverse_h_entry = cur_inverse + 1;
            }

            // Mark as belonging to valid chain
            if make_valid {
                let key = parent.block_hash().unwrap();

                if let Some(validation) = self.validations_mapping.get_mut(&key) {
                    *validation = ValidationStatus::BelongsToValidChain;
                } else {
                    self.validations_mapping.insert(key, ValidationStatus::BelongsToValidChain);
                }
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
                self.process_orphans(height + 1);

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

                        let mut status = ValidationStatus::ValidChainTip;
                        let mut tip = block.clone();
                        let mut _inverse_height = 0;

                        self.write_orphan(block, ValidationStatus::ValidChainTip, 0);
                        self.attempt_attach_valid(&mut tip, &mut _inverse_height, &mut status);

                        if let ValidationStatus::ValidChainTip = status {
                            // Do nothing
                        } else {
                            self.attempt_switch(tip);
                        }

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
                                ValidationStatus::DisconnectedTip => {
                                    let head = self.disconnected_tips_mapping.get(&parent_hash).unwrap().clone();
                                    let tips = self.disconnected_heads_mapping.get_mut(&head).unwrap();
                                    let (largest_height, _) = self.disconnected_heads_heights.get(&head).unwrap();

                                    // Change the status of the old tip
                                    *parent_status = ValidationStatus::BelongsToDisconnected;

                                    // Replace old tip in mappings
                                    tips.remove(&parent_hash);
                                    tips.insert(block_hash.clone());

                                    // Replace largest height if this is the case
                                    if block.height() > *largest_height {
                                        self.disconnected_heads_heights.insert(head.clone(), (block.height(), block_hash.clone()));
                                    }

                                    self.disconnected_tips_mapping.insert(block_hash.clone(), head.clone());
                                    let status = self.attempt_attach(&block_hash, ValidationStatus::DisconnectedTip);

                                    if let ValidationStatus::DisconnectedTip = status {
                                        self.recurse_inverse(block.clone(), 0, false);
                                    } else {
                                        self.disconnected_tips_mapping.remove(&block_hash);
                                    }

                                    self.disconnected_tips_mapping.remove(&parent_hash);
                                    self.write_orphan(block, status, 0);
                                }
                                ValidationStatus::ValidChainTip => {
                                    // Change status of old tip
                                    *parent_status = ValidationStatus::BelongsToValidChain;

                                    let mut status = ValidationStatus::ValidChainTip;
                                    let mut tip = block.clone();
                                    let mut inverse_height = 0;

                                    // Mark orphan as the new tip
                                    self.write_orphan(block.clone(), status, inverse_height);

                                    // Attempt to attach to disconnected chains
                                    self.attempt_attach_valid(&mut tip, &mut inverse_height, &mut status);

                                    // Recurse parents and modify their inverse heights
                                    self.recurse_inverse(block.clone(), inverse_height, inverse_height == 0);

                                    // Update tips set
                                    self.valid_tips.remove(&parent_hash);
                                    self.valid_tips.insert(tip.block_hash().unwrap());

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
                                    let tips = self.disconnected_heads_mapping.get_mut(&head).unwrap();

                                    tips.insert(block_hash.clone());
                                    self.disconnected_tips_mapping.insert(block_hash.clone(), head.clone());
                                    
                                    let status = self.attempt_attach(&block_hash, ValidationStatus::DisconnectedTip);

                                    if let ValidationStatus::DisconnectedTip = status {
                                        self.disconnected_tips_mapping.insert(block_hash.clone(), head);
                                        self.recurse_inverse(block.clone(), 0, false);
                                    }

                                    self.write_orphan(block, status, 0);
                                }
                                ValidationStatus::BelongsToValidChain => {
                                    let mut status = ValidationStatus::ValidChainTip;
                                    let mut tip = block.clone();
                                    let mut inverse_height = 0;

                                    // Write tip to valid tips set
                                    self.valid_tips.insert(tip.block_hash().unwrap());

                                    // Attempt to attach disconnected chains 
                                    // to the new valid tip.
                                    self.attempt_attach_valid(&mut tip, &mut inverse_height, &mut status);

                                    // Write orphan, recurse and update inverse heights,
                                    // then attempt to switch the canonical chain.
                                    self.write_orphan(block, status, inverse_height);
                                    self.recurse_inverse(tip.clone(), inverse_height, inverse_height == 0);
                                    self.attempt_switch(tip);
                                }
                            }

                            Ok(())
                        } else {
                            // Add first to disconnected mappings
                            let mut set = HashSet::new();
                            set.insert(block_hash.clone());

                            // Init disconnected mappings
                            self.disconnected_heads_mapping.insert(block_hash.clone(), set);
                            self.disconnected_tips_mapping.insert(block_hash.clone(), block_hash.clone());
                            self.disconnected_heads_heights.insert(block_hash.clone(), (block.height(), block_hash.clone()));
                            
                            // Init heights mappings
                            if let Some(entry) = self.heights_mapping.get_mut(&block.height()) {
                                entry.insert(block_hash.clone(), 0);
                            } else {
                                let mut hm = HashMap::new();
                                hm.insert(block_hash.clone(), 0);

                                self.heights_mapping.insert(block.height(), hm);
                            }

                            // Add block to orphan pool
                            self.orphan_pool.insert(block_hash.clone(), block.clone());

                            let status = self.attempt_attach(&block_hash, ValidationStatus::DisconnectedTip);
                            let mut found_match = None;

                            // Attempt to attach the new disconnected 
                            // chain to any valid chain.
                            for tip_hash in self.valid_tips.iter() {
                                let tip = self.orphan_pool.get(tip_hash).unwrap();

                                if parent_hash == tip.block_hash().unwrap() {
                                    found_match = Some(tip);
                                    break;
                                }
                            }

                            if let Some(tip) = found_match {
                                let mut _status = ValidationStatus::ValidChainTip;
                                let mut _tip = tip.clone();
                                let mut _inverse_height = 0;

                                self.write_orphan(block, status, 0);
                                self.attempt_attach_valid(&mut _tip, &mut _inverse_height, &mut _status);

                                Ok(())
                            } else {
                                self.write_orphan(block, status, 0);
                                Ok(())
                            }
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

    #[test]
    fn stages_append_test1() {
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

        hard_chain.append_block(E_second.clone()).unwrap();
        hard_chain.append_block(F_second.clone()).unwrap();

        assert_eq!(hard_chain.height(), 0);

        // We should have a disconnected chain of `E''` and `F''`
        // with the tip of `E''` pointing to `F''`.
        assert_eq!(*hard_chain.disconnected_tips_mapping.get(&F_second.block_hash().unwrap()).unwrap(), E_second.block_hash().unwrap());
        let heads_mapping = hard_chain.disconnected_heads_mapping.get(&E_second.block_hash().unwrap()).unwrap();
        let (largest_height, largest_tip) = hard_chain.disconnected_heads_heights.get(&E_second.block_hash().unwrap()).unwrap();
        assert!(heads_mapping.contains(&F_second.block_hash().unwrap()));
        assert_eq!(*largest_height, F_second.height());
        assert_eq!(largest_tip, &F_second.block_hash().unwrap());

        hard_chain.append_block(A.clone()).unwrap();
        hard_chain.append_block(B.clone()).unwrap();

        assert_eq!(hard_chain.height(), 2);
        assert_eq!(hard_chain.canonical_tip(), B);

        hard_chain.append_block(F.clone()).unwrap();
        hard_chain.append_block(G.clone()).unwrap();

        assert_eq!(hard_chain.height(), 2);
        assert_eq!(hard_chain.canonical_tip(), B);

        // We should have a disconnected chain of `F` and `G`
        // with the tip of `G` pointing to `F`.
        assert_eq!(*hard_chain.disconnected_tips_mapping.get(&G.block_hash().unwrap()).unwrap(), F.block_hash().unwrap());
        let heads_mapping = hard_chain.disconnected_heads_mapping.get(&F.block_hash().unwrap()).unwrap();
        let (largest_height, largest_tip) = hard_chain.disconnected_heads_heights.get(&F.block_hash().unwrap()).unwrap();
        assert!(heads_mapping.contains(&G.block_hash().unwrap()));
        assert_eq!(*largest_height, G.height());
        assert_eq!(largest_tip, &G.block_hash().unwrap());
        assert_eq!(hard_chain.height(), 2);
        assert_eq!(hard_chain.canonical_tip(), B);

        // We now append `B'` and the canonical tip should still be `B`
        hard_chain.append_block(B_prime.clone()).unwrap();

        assert_eq!(hard_chain.height(), 2);
        assert_eq!(hard_chain.canonical_tip(), B);

        hard_chain.append_block(C_prime.clone()).unwrap();

        assert_eq!(hard_chain.height(), 3);
        assert_eq!(hard_chain.canonical_tip(), C_prime);

        hard_chain.append_block(C.clone()).unwrap();
        assert_eq!(hard_chain.height(), 3);
        assert_eq!(hard_chain.canonical_tip(), C_prime);

        hard_chain.append_block(D.clone()).unwrap();

        assert_eq!(hard_chain.height(), 4);
        assert_eq!(hard_chain.canonical_tip(), D);

        // After appending `E` the chain should connect the old tip
        // which is `D` to our previous disconnected chain of `F` -> `G`.
        hard_chain.append_block(E.clone()).unwrap();

        assert_eq!(hard_chain.height(), 7);
        assert_eq!(hard_chain.canonical_tip(), G);
    }

    #[test]
    fn stages_append_test2() {
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

        hard_chain.append_block(A.clone()).unwrap();

        assert_eq!(hard_chain.height(), 1);
        
        hard_chain.append_block(E_second.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&E_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        hard_chain.append_block(D_second.clone()).unwrap();

        assert_eq!(*hard_chain.validations_mapping.get(&E_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);

        hard_chain.append_block(F_second.clone()).unwrap();

        assert_eq!(*hard_chain.validations_mapping.get(&E_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&F_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        // We should have a disconnected chain of `E''` and `F''`
        // with the tip of `D''` pointing to `F''`.
        assert_eq!(*hard_chain.disconnected_tips_mapping.get(&F_second.block_hash().unwrap()).unwrap(), D_second.block_hash().unwrap());
        let heads_mapping = hard_chain.disconnected_heads_mapping.get(&D_second.block_hash().unwrap()).unwrap();
        let (largest_height, largest_tip) = hard_chain.disconnected_heads_heights.get(&D_second.block_hash().unwrap()).unwrap();
        assert!(heads_mapping.contains(&F_second.block_hash().unwrap()));
        assert_eq!(*largest_height, F_second.height());
        assert_eq!(largest_tip, &F_second.block_hash().unwrap());

        assert_eq!(hard_chain.height(), 1);
        assert_eq!(hard_chain.canonical_tip(), A);

        hard_chain.append_block(C.clone()).unwrap();
        hard_chain.append_block(D.clone()).unwrap();
        hard_chain.append_block(F.clone()).unwrap();
        hard_chain.append_block(E.clone()).unwrap();
        hard_chain.append_block(G.clone()).unwrap();

        assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&E.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        assert_eq!(hard_chain.height(), 1);
        assert_eq!(hard_chain.canonical_tip(), A);

        // We now append `B'` and the canonical tip should be `B'`
        hard_chain.append_block(B_prime.clone()).unwrap();

        assert_eq!(hard_chain.height(), 2);
        assert_eq!(hard_chain.canonical_tip(), B_prime);

        hard_chain.append_block(C_second.clone()).unwrap();

        // The chain should now be pointing to `F''` as being the canonical tip
        assert_eq!(hard_chain.height(), 6);
        assert_eq!(hard_chain.canonical_tip(), F_second);

        // We now append `B` and the chain should switch to `G` as the canonical tip
        hard_chain.append_block(B.clone()).unwrap();

        assert_eq!(hard_chain.height(), 7);
        assert_eq!(hard_chain.canonical_tip(), G);
    }

    #[test]
    /// Assertions in stages on random order
    /// of appended blocks.
    fn stages_append_test3() {
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

        println!("PUSHING C'': {:?}", C_second.block_hash().unwrap());
        hard_chain.append_block(C_second.clone()).unwrap();
        let C_second_ih = hard_chain.heights_mapping.get(&C_second.height()).unwrap().get(&C_second.block_hash().unwrap()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*C_second_ih, 0);

        println!("PUSHING D': {:?}", D_prime.block_hash().unwrap());
        hard_chain.append_block(D_prime.clone()).unwrap();
        let C_second_ih = hard_chain.heights_mapping.get(&C_second.height()).unwrap().get(&C_second.block_hash().unwrap()).unwrap();
        let D_prime_ih = hard_chain.heights_mapping.get(&D_prime.height()).unwrap().get(&D_prime.block_hash().unwrap()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*C_second_ih, 0);
        assert_eq!(*D_prime_ih, 0);

        println!("PUSHING F: {:?}", F.block_hash().unwrap());
        hard_chain.append_block(F.clone()).unwrap();
        println!("PUSHING D'': {:?}", D_second.block_hash().unwrap());
        hard_chain.append_block(D_second.clone()).unwrap();
        let C_second_ih = hard_chain.heights_mapping.get(&C_second.height()).unwrap().get(&C_second.block_hash().unwrap()).unwrap();
        let D_prime_ih = hard_chain.heights_mapping.get(&D_prime.height()).unwrap().get(&D_prime.block_hash().unwrap()).unwrap();
        let D_second_ih = hard_chain.heights_mapping.get(&D_second.height()).unwrap().get(&D_second.block_hash().unwrap()).unwrap();
        let F_ih = hard_chain.heights_mapping.get(&F.height()).unwrap().get(&F.block_hash().unwrap()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*C_second_ih, 1);
        assert_eq!(*D_prime_ih, 0);
        assert_eq!(*D_second_ih, 0);
        assert_eq!(*F_ih, 0);

        println!("PUSHING C': {:?}", C_prime.block_hash().unwrap());
        hard_chain.append_block(C_prime.clone()).unwrap();
        let C_second_ih = hard_chain.heights_mapping.get(&C_second.height()).unwrap().get(&C_second.block_hash().unwrap()).unwrap();
        let C_prime_ih = hard_chain.heights_mapping.get(&C_prime.height()).unwrap().get(&C_prime.block_hash().unwrap()).unwrap();
        let D_prime_ih = hard_chain.heights_mapping.get(&D_prime.height()).unwrap().get(&D_prime.block_hash().unwrap()).unwrap();
        let D_second_ih = hard_chain.heights_mapping.get(&D_second.height()).unwrap().get(&D_second.block_hash().unwrap()).unwrap();
        let F_ih = hard_chain.heights_mapping.get(&F.height()).unwrap().get(&F.block_hash().unwrap()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        
        println!("DEBUG HEIGHTS MAPPING: {:?}", hard_chain.heights_mapping);
        assert_eq!(*C_second_ih, 1);
        assert_eq!(*C_prime_ih, 1);
        assert_eq!(*D_prime_ih, 0);
        assert_eq!(*D_second_ih, 0);
        assert_eq!(*F_ih, 0);

        println!("PUSHING D: {:?}", D.block_hash().unwrap());
        hard_chain.append_block(D.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        println!("PUSHING G: {:?}", G.block_hash().unwrap());
        hard_chain.append_block(G.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        println!("PUSHING B': {:?}", B_prime.block_hash().unwrap());
        hard_chain.append_block(B_prime.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        println!("PUSHING D''': {:?}", D_tertiary.block_hash().unwrap());
        hard_chain.append_block(D_tertiary.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        println!("PUSHING C: {:?}", C.block_hash().unwrap());
        hard_chain.append_block(C.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        println!("PUSHING E': {:?}", E_prime.block_hash().unwrap());
        hard_chain.append_block(E_prime.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&E_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);

        println!("PUSHING B: {:?}", B.block_hash().unwrap());
        hard_chain.append_block(B.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&E_prime.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(hard_chain.valid_tips, HashSet::new());

        println!("PUSHING A: {:?}", A.block_hash().unwrap());
        hard_chain.append_block(A.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&B.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        let mut tips = HashSet::new();
        tips.insert(D.block_hash().unwrap());
        tips.insert(D_second.block_hash().unwrap());
        tips.insert(D_tertiary.block_hash().unwrap());

        println!("DEBUG B HASH: {:?}", B.block_hash().unwrap());
        println!("DEBUG D HASH: {:?}", D.block_hash().unwrap());

        assert_eq!(hard_chain.valid_tips, tips);
        assert_eq!(hard_chain.height(), 5);
        assert_eq!(hard_chain.canonical_tip(), E_prime);

        println!("PUSHING E''");
        hard_chain.append_block(E_second.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&B.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        let mut tips = HashSet::new();
        tips.insert(D.block_hash().unwrap());
        tips.insert(E_second.block_hash().unwrap());
        tips.insert(D_tertiary.block_hash().unwrap());

        assert_eq!(hard_chain.valid_tips, tips);
        assert_eq!(hard_chain.height(), 5);
        assert_eq!(hard_chain.canonical_tip(), E_prime);

        println!("PUSHING F''");
        hard_chain.append_block(F_second.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&E_prime.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToDisconnected);
        assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::DisconnectedTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        let mut tips = HashSet::new();
        tips.insert(D.block_hash().unwrap());
        tips.insert(E_prime.block_hash().unwrap());
        tips.insert(D_tertiary.block_hash().unwrap());

        println!("DEBUG VALID_TIPS: {:?}", hard_chain.valid_tips);
        println!("DEBUG ORACLE TIPS: {:?}", tips);

        assert_eq!(hard_chain.valid_tips, tips);
        assert_eq!(hard_chain.height(), 6);
        assert_eq!(hard_chain.canonical_tip(), F_second);

        println!("PUSHING E");
        hard_chain.append_block(E.clone()).unwrap();
        assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&E_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&F_second.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
        assert_eq!(*hard_chain.validations_mapping.get(&E_prime.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
        let mut tips = HashSet::new();
        tips.insert(F_second.block_hash().unwrap());
        tips.insert(E_prime.block_hash().unwrap());
        tips.insert(D_tertiary.block_hash().unwrap());

        assert_eq!(hard_chain.valid_tips, tips);
        assert_eq!(hard_chain.height(), 7);
        assert_eq!(hard_chain.canonical_tip(), G);
    }

    quickcheck! {
        /// Stress test of chain append.
        /// 
        /// We have a graph of chains of blocks with 
        /// the following structure:
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
            println!("DEBUG STRESS TEST");

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
                A.clone(),
                B.clone(),
                C.clone(),
                D.clone(),
                E.clone(),
                F.clone(),
                G.clone(),
                B_prime.clone(),
                C_prime.clone(),
                D_prime.clone(),
                E_prime.clone(),
                C_second.clone(),
                D_second.clone(),
                E_second.clone(),
                F_second.clone(),
                D_tertiary.clone()
            ];

            // Shuffle blocks
            thread_rng().shuffle(&mut blocks);

            let mut block_letters = HashMap::new();

            block_letters.insert(A.block_hash().unwrap(), "A");
            block_letters.insert(B.block_hash().unwrap(), "B");
            block_letters.insert(C.block_hash().unwrap(), "C");
            block_letters.insert(D.block_hash().unwrap(), "D");
            block_letters.insert(E.block_hash().unwrap(), "E");
            block_letters.insert(F.block_hash().unwrap(), "F");
            block_letters.insert(G.block_hash().unwrap(), "G");
            block_letters.insert(B_prime.block_hash().unwrap(), "B'");
            block_letters.insert(C_prime.block_hash().unwrap(), "C'");
            block_letters.insert(D_prime.block_hash().unwrap(), "D'");
            block_letters.insert(E_prime.block_hash().unwrap(), "E'");
            block_letters.insert(C_second.block_hash().unwrap(), "C''");
            block_letters.insert(D_second.block_hash().unwrap(), "D''");
            block_letters.insert(E_second.block_hash().unwrap(), "E''");
            block_letters.insert(F_second.block_hash().unwrap(), "F''");
            block_letters.insert(D_tertiary.block_hash().unwrap(), "D'''");

            for b in blocks {
                println!("DEBUG BLOCK_LETTER: {}, BLOCK: {:?}", block_letters.get(&b.block_hash().unwrap()).unwrap(), b);
                hard_chain.append_block(b).unwrap();
            
                if let Some(letter) = block_letters.get(&hard_chain.canonical_tip.block_hash().unwrap()) {
                    println!("DEBUG CHAIN_CANONICAL_TIP: {:?}", letter);
                } else {
                    println!("DEBUG CHAIN_CANONICAL_TIP: GEN");
                }
            }

            assert_eq!(hard_chain.height(), 7);
            assert_eq!(hard_chain.canonical_tip(), G);

            true
        }

        fn it_rewinds_correctly1() -> bool {
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

            let blocks = vec![
                A.clone(),
                B.clone(),
                C.clone(),
                D.clone(),
                E.clone(),
                F.clone(),
                G.clone(),
            ];

            for b in blocks {
                hard_chain.append_block(b).unwrap();
            }

            assert_eq!(hard_chain.height(), 7);
            assert_eq!(hard_chain.canonical_tip(), G.clone());
            assert!(hard_chain.query(&A.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&B.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&C.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&D.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&E.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&F.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&G.block_hash().unwrap()).is_some());

            hard_chain.rewind(&B.block_hash().unwrap()).unwrap();

            assert_eq!(hard_chain.height(), 2);
            assert_eq!(hard_chain.canonical_tip(), B);
            assert!(hard_chain.valid_tips.contains(&G.block_hash().unwrap()));
            assert!(hard_chain.query(&A.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&B.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&C.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&D.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&E.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&F.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&G.block_hash().unwrap()).is_none());
            assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&E.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            let mut tips = HashSet::new();
            tips.insert(G.block_hash().unwrap());

            assert_eq!(hard_chain.valid_tips, tips);

            true
        }

        fn it_rewinds_correctly2() -> bool {
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

            let blocks = vec![
                A.clone(),
                B.clone(),
                C.clone(),
                D.clone(),
                E.clone(),
                F.clone(),
                G.clone(),
                B_prime.clone(),
                C_prime.clone(),
                D_prime.clone(),
                E_prime.clone(),
                C_second.clone(),
                D_second.clone(),
                E_second.clone(),
                F_second.clone(),
                D_tertiary.clone(),
            ];

            for b in blocks {
                hard_chain.append_block(b).unwrap();
            }

            assert_eq!(hard_chain.height(), 7);
            assert_eq!(hard_chain.canonical_tip(), G.clone());
            assert!(hard_chain.query(&A.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&B.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&C.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&D.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&E.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&F.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&G.block_hash().unwrap()).is_some());
            assert!(hard_chain.query(&B_prime.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&C_prime.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&D_prime.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&E_prime.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&C_second.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&D_second.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&E_second.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&F_second.block_hash().unwrap()).is_none());
            assert!(hard_chain.query(&D_tertiary.block_hash().unwrap()).is_none());
            let mut tips = HashSet::new();
            tips.insert(F_second.block_hash().unwrap());
            tips.insert(E_prime.block_hash().unwrap());
            tips.insert(D_tertiary.block_hash().unwrap());

            assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&C_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&E_prime.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&E_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&F_second.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            let mut tips = HashSet::new();
            tips.insert(F_second.block_hash().unwrap());
            tips.insert(E_prime.block_hash().unwrap());
            tips.insert(D_tertiary.block_hash().unwrap());
            assert_eq!(tips, hard_chain.valid_tips);

            hard_chain.rewind(&B.block_hash().unwrap()).unwrap();

            assert_eq!(*hard_chain.validations_mapping.get(&B_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&D_prime.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&E_prime.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            assert_eq!(*hard_chain.validations_mapping.get(&C_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&D_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&E_second.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&F_second.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            assert_eq!(*hard_chain.validations_mapping.get(&D_tertiary.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            assert_eq!(*hard_chain.validations_mapping.get(&C.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&D.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&E.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&F.block_hash().unwrap()).unwrap(), ValidationStatus::BelongsToValidChain);
            assert_eq!(*hard_chain.validations_mapping.get(&G.block_hash().unwrap()).unwrap(), ValidationStatus::ValidChainTip);
            let mut tips = HashSet::new();
            tips.insert(F_second.block_hash().unwrap());
            tips.insert(E_prime.block_hash().unwrap());
            tips.insert(D_tertiary.block_hash().unwrap());
            tips.insert(G.block_hash().unwrap());
            assert_eq!(tips, hard_chain.valid_tips);

            true
        }
    }
}