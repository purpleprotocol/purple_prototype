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

use persistence::{PersistentDb, STATE_REGISTRY};
use common::{StorageLocation, Checkpointable};
use consensus::PoolState;

/// Wrapper over the `StateChain` associated chain state.
#[derive(Clone, Debug)]
pub struct ChainState {
    /// Database storing the ledger ephemeral state.
    pub(crate) db: PersistentDb,

    /// The current validator pool state
    pub(crate) pool_state: PoolState,
}

impl ChainState {
    const POOL_STATE_KEY: &'static [u8] = b"pool_state";
    
    pub fn new(db: PersistentDb) -> ChainState {
        ChainState {
            db,
            pool_state: PoolState::new(0, 1000) // TODO: Retrieve/calculate pool state from database
        }
    }

    /// Returns true if the underlying `PersistentDb` 
    /// is canonical i.e. not a checkpoint.
    pub fn is_canonical(&self) -> bool {
        self.db.is_canonical()
    }

    pub fn make_canonical(&mut self) -> Result<(), ()> {
        self.db.make_canonical()
    }
}

impl Checkpointable for ChainState {
    fn checkpoint(&self, height: u64) -> u64 {
        #[cfg(not(feature = "test"))]
        {
            let mut registry = STATE_REGISTRY.lock();
            registry.checkpoint(self.db.db_ref.clone().unwrap(), height)
        }

        #[cfg(feature = "test")]
        {
            STATE_REGISTRY.with(|registry| {
                let mut registry = registry.lock();
                registry.checkpoint(self.db.db_ref.clone().unwrap(), height)
            })
        }
    }

    fn fetch_existing_checkpoints() -> Option<Vec<(u64, u64)>> {
        #[cfg(not(feature = "test"))]
        {
            let registry = STATE_REGISTRY.lock();
            registry.retrieve_ids_and_heights()
        }

        #[cfg(feature = "test")]
        {
            STATE_REGISTRY.with(|registry| {
                let mut registry = registry.lock();
                registry.retrieve_ids_and_heights()
            })
        }
    }

    fn delete_checkpoint(id: u64) -> Result<(), ()> {
        #[cfg(not(feature = "test"))]
        {
            let mut registry = STATE_REGISTRY.lock();
            registry.delete_checkpoint(id)
        }

        #[cfg(feature = "test")]
        {
            STATE_REGISTRY.with(|registry| {
                let mut registry = registry.lock();
                registry.delete_checkpoint(id)
            })
        }
    }

    fn load_from_disk(id: u64) -> Result<ChainState, ()> {
        let database = {
            #[cfg(not(feature = "test"))]
            {
                let registry = STATE_REGISTRY.lock();
                registry.load_from_disk(id)?
            }

            #[cfg(feature = "test")]
            {
                STATE_REGISTRY.with(|registry| {
                    let registry = registry.lock();
                    registry.load_from_disk(id)
                })?
            }
        };

        Ok(ChainState::new(database))
    }

    fn storage_location(&self) -> StorageLocation {
        if self.db.memory_db.is_empty() {
            StorageLocation::Disk
        } else {
            StorageLocation::Memory
        }
    }

    fn make_canonical(old_state: &Self, mut new_state: Self) -> Self { 
        assert!(old_state.is_canonical());
        
        if new_state.is_canonical() {
            // Just flush changes if both states are canonical
            new_state.db.flush();
            new_state
        } else {
            new_state.make_canonical().unwrap();
            new_state.db.flush();
            new_state
        }
    }
}