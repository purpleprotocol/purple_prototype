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
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicUsize};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StorageLocation {
    Disk,
    Memory
}

/// Trait for any state that can be checkpointed
/// and that can be reloaded from checkpoints.
pub trait Checkpointable: Sized + Debug + Clone {
    /// Creates a checkpoint of the current state and 
    /// returns the checkpoint id associated with it.
    fn checkpoint(&self, height: u64) -> u64;

    /// Returns a vector containing existing checkpoint ids and
    /// their corresponding height if there are any listed.
    fn fetch_existing_checkpoints() -> Option<Vec<(u64, u64)>>;

    /// Deletes the checkpoint with the given id
    fn delete_checkpoint(id: u64) -> Result<(), ()>;

    /// Reloads the state from the disk checkpoint with the given id.
    fn load_from_disk(id: u64) -> Result<Self, ()>;

    /// Returns the storage location of the checkpoint.
    fn storage_location(&self) -> StorageLocation;
}

lazy_static! {
    static ref CHECKPOINT_ID: AtomicUsize = AtomicUsize::new(1);
    static ref BACKEND_ID: AtomicUsize = AtomicUsize::new(0);
    static ref DUMMY_BACKEND: Mutex<HashMap<u64, HashMap<u64, DummyCheckpoint>>> = Mutex::new(HashMap::new());
}

#[derive(Debug)]
/// Placeholder checkpoint type
pub struct DummyCheckpoint {
    id: Arc<Mutex<u64>>,
    backend_id: u64,
    location: Arc<Mutex<StorageLocation>>,
    height: Arc<Mutex<u64>>,
}

impl Clone for DummyCheckpoint {
    fn clone(&self) -> Self {
        let id = self.id.lock();
        let location = self.location.lock();
        let height = self.height.lock();
        
        DummyCheckpoint {
            id: Arc::new(Mutex::new(id.clone())),
            backend_id: self.backend_id,
            location: Arc::new(Mutex::new(location.clone())),
            height: Arc::new(Mutex::new(height.clone())),
        }
    }
}

impl DummyCheckpoint {
    pub fn new(location: StorageLocation, height: u64, backend_id: u64) -> DummyCheckpoint {
        let id = CHECKPOINT_ID.fetch_add(1, Ordering::Relaxed) as u64;
        DummyCheckpoint { 
            location: Arc::new(Mutex::new(location)), 
            height: Arc::new(Mutex::new(height)), 
            id: Arc::new(Mutex::new(id)),
            backend_id,
        }
    }

    pub fn genesis() -> DummyCheckpoint {
        DummyCheckpoint::new(StorageLocation::Disk, 0, BACKEND_ID.fetch_add(1, Ordering::Relaxed) as u64)
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

    pub fn clear_checkpoints() {
        let mut db = DUMMY_BACKEND.lock();
        db.clear();
    }
}

impl Checkpointable for DummyCheckpoint {
    fn checkpoint(&self, _height: u64) -> u64 {
        let mut id = self.id.lock();
        let mut location = self.location.lock();
        *id = CHECKPOINT_ID.fetch_add(1, Ordering::Relaxed) as u64;
        *location = StorageLocation::Disk;

        let mut db = DUMMY_BACKEND.lock();
        let mut db = db.get_mut(&self.backend_id).unwrap();
        db.insert(id.clone(), self.clone());

        id.clone()
    }

    fn fetch_existing_checkpoints() -> Option<Vec<(u64, u64)>> {
        None
    }

    fn delete_checkpoint(id: u64) -> Result<(), ()> {
        let mut db = DUMMY_BACKEND.lock();
        let mut db = db.get_mut(&id).unwrap();

        if let Some(_) = db.remove(&id) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn load_from_disk(id: u64) -> Result<DummyCheckpoint, ()> {
        let db = DUMMY_BACKEND.lock();
        let db = db.get(&id).unwrap();

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