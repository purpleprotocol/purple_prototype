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

    /// Reloads the state from the disk checkpoint with the given id.
    fn load_from_disk(id: u64) -> Result<Self, ()>;

    /// Returns the storage location of the checkpoint.
    fn storage_location(&self) -> StorageLocation;
}

#[derive(Clone)]
/// Placeholder checkpoint type
pub struct DummyCheckpoint {
    location: StorageLocation
}

impl DummyCheckpoint {
    pub fn new(location: StorageLocation) -> DummyCheckpoint {
        DummyCheckpoint { location }
    }
}

impl Checkpointable for DummyCheckpoint {
    fn checkpoint(&self) -> u64 {
        0
    }

    fn load_from_disk(_id: u64) -> Result<DummyCheckpoint, ()> {
        Ok(DummyCheckpoint::new(StorageLocation::Disk))
    }

    fn storage_location(&self) -> StorageLocation {
        self.location
    }
}