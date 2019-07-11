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

use crate::persistent_db::PersistentDb;
use crate::init::*;
use std::sync::Arc;
use std::path::PathBuf;
use rocksdb::DB;
use rocksdb::checkpoint::Checkpoint;
use parking_lot::Mutex;

lazy_static! {
    pub static ref STATE_REGISTRY: Mutex<StateRegistry> = {
        if !is_initialized() {
            panic!("Persistence module not initialized! Call `persistence::init()` before using anything");
        }

        let working_dir = unsafe {
            WORKING_DIR.clone().unwrap()
        };
        
        Mutex::new(StateRegistry::new(working_dir))
    };
}

/// Registry for ephemeral state db handles.
#[derive(Debug)]
pub struct StateRegistry {
    /// The id of the latest snapshot
    latest_id: u64,

    /// The directory that contains all databases
    working_dir: PathBuf,
}

impl StateRegistry {
    pub fn new(working_dir: PathBuf) -> Self {
        StateRegistry {
            latest_id: 0, // TODO: Load this from a database
            working_dir,
        }
    }

    // TODO: Maybe return a `Result`.
    pub fn checkpoint(&mut self, db_ref: Arc<DB>) -> u64 {
        let working_dir = unsafe {
            WORKING_DIR.clone().unwrap()
        };

        let next_id = self.latest_id + 1;
        let checkpoint = Checkpoint::new(db_ref.as_ref()).unwrap();
        let checkpoint_path = working_dir.join(&format!("{}", next_id));
        checkpoint.create_checkpoint(checkpoint_path).unwrap();

        self.latest_id = next_id;
        next_id
    }
}