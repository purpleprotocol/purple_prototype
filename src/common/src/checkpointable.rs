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

use lazy_static::*;
use hashbrown::HashMap;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicUsize};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StorageLocation {
    Disk,
    Memory
}

/// Trait for any state that can be checkpointed
/// and that can be reloaded from checkpoints.
pub trait Checkpointable: Sized {
    /// Creates a checkpoint of the current state and 
    /// returns the checkpoint id associated with it.
    fn checkpoint(&self) -> u64;

    /// Deletes the checkpoint with the given id
    fn delete_checkpoint(id: u64) -> Result<(), ()>;

    /// Reloads the state from the disk checkpoint with the given id.
    fn load_from_disk(id: u64) -> Result<Self, ()>;

    /// Returns the storage location of the checkpoint.
    fn storage_location(&self) -> StorageLocation;
}

lazy_static! {
    static ref DUMMY_BACKEND: Mutex<HashMap<u64, DummyCheckpoint>> = Mutex::new(HashMap::new());
    static ref CHECKPOINT_ID: AtomicUsize = AtomicUsize::new(1);
    static ref GENESIS_DUMMY: DummyCheckpoint = DummyCheckpoint::new(StorageLocation::Disk, 0);
}

#[derive(Clone)]
/// Placeholder checkpoint type
pub struct DummyCheckpoint {
    id: Arc<Mutex<u64>>,
    location: Arc<Mutex<StorageLocation>>,
    height: Arc<Mutex<u64>>,
}

impl DummyCheckpoint {
    pub fn new(location: StorageLocation, height: u64) -> DummyCheckpoint {
        let id = CHECKPOINT_ID.fetch_add(1, Ordering::Relaxed) as u64;
        DummyCheckpoint { 
            location: Arc::new(Mutex::new(location)), 
            height: Arc::new(Mutex::new(height)), 
            id: Arc::new(Mutex::new(id))
        }
    }

    pub fn genesis() -> DummyCheckpoint {
        GENESIS_DUMMY.clone()
    }

    pub fn increment(&mut self) {
        let mut height = self.height.lock();
        let mut location = self.location.lock();

        *height += 1;
        *location = StorageLocation::Memory;
    }

    pub fn height(&self) -> u64 {
        let height = self.height.lock();
        height.clone()
    }
}

impl Checkpointable for DummyCheckpoint {
    fn checkpoint(&self) -> u64 {
        let mut id = self.id.lock();
        let mut location = self.location.lock();
        *id = CHECKPOINT_ID.fetch_add(1, Ordering::Relaxed) as u64;
        *location = StorageLocation::Disk;
        id.clone()
    }

    fn delete_checkpoint(id: u64) -> Result<(), ()> {
        let mut db = DUMMY_BACKEND.lock();

        if let Some(_) = db.remove(&id) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn load_from_disk(id: u64) -> Result<DummyCheckpoint, ()> {
        let db = DUMMY_BACKEND.lock();

        if let Some(result) = db.get(&id) {
            Ok(result.clone())
        } else {
            Err(())
        }
    }

    fn storage_location(&self) -> StorageLocation {
        let location = self.location.lock();
        location.clone()
    }
}