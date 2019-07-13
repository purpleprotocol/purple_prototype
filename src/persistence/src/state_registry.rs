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

    /// The internal registry database
    inner_db: DB,

    /// The directory that contains all databases
    working_dir: PathBuf,
}

impl StateRegistry {
    const LATEST_ID_KEY: &'static [u8] = b"latest_id";

    pub fn new(working_dir: PathBuf) -> Self {
        let internal_path = working_dir.join("internal_db");
        let inner_db = crate::open_database_no_checks(&internal_path);
        let latest_id = if let Some(latest_id) = inner_db.get(Self::LATEST_ID_KEY).unwrap() {
            decode_be_u64!(latest_id).unwrap()
        } else {
            inner_db.put(Self::LATEST_ID_KEY, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            0
        };

        StateRegistry {
            latest_id,
            inner_db,
            working_dir,
        }
    }

    // TODO: Maybe return a `Result` instead of panicking.
    pub fn checkpoint(&mut self, db_ref: Arc<DB>) -> u64 {
        let working_dir = unsafe {
            WORKING_DIR.clone().unwrap()
        };

        let latest_id = if let Some(latest_id) = self.inner_db.get(Self::LATEST_ID_KEY).unwrap() {
            decode_be_u64!(latest_id).unwrap()
        } else {
            unreachable!();
        };

        let next_id = latest_id + 1;
        let checkpoint = Checkpoint::new(db_ref.as_ref()).unwrap();
        let checkpoint_path = working_dir.join(&format!("{}", next_id));
        checkpoint.create_checkpoint(checkpoint_path).unwrap();

        // Write next id
        self.inner_db.put(Self::LATEST_ID_KEY, encode_be_u64!(next_id)).unwrap();
        self.latest_id = next_id;

        next_id
    }
}