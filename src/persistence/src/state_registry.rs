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
use crate::persistent_db::PersistentDb;
use std::sync::Arc;
use std::path::PathBuf;
use byteorder::{BigEndian, ReadBytesExt};
use rocksdb::DB;
use rocksdb::checkpoint::Checkpoint;
use parking_lot::Mutex;
use std::fs;
use std::io::Cursor;
use rlp::RlpStream;

#[cfg(not(feature = "test"))]
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

#[cfg(feature = "test")]
thread_local! {
    pub static STATE_REGISTRY: Mutex<StateRegistry> = {
        if !is_initialized() {
            panic!("Persistence module not initialized! Call `persistence::init()` before using anything");
        }

        let working_dir = WORKING_DIR.with(|working_dir| working_dir.borrow().clone().unwrap());
        Mutex::new(StateRegistry::new(working_dir))
    };
}

/// Registry for ephemeral state db handles.
#[derive(Debug)]
pub struct StateRegistry {
    /// The id of the latest snapshot
    latest_id: u64,

    /// The internal registry database
    inner_db: PersistentDb,

    /// The directory that contains all databases
    working_dir: PathBuf,
}

impl StateRegistry {
    const LATEST_ID_KEY: &'static [u8] = b"latest_id";
    const IDS_AND_HEIGHTS_KEY: &'static [u8] = b"ids_and_heights";

    pub fn new(working_dir: PathBuf) -> Self {
        #[cfg(not(feature = "test"))]
        let inner_db = unsafe { REGISTRY_DB.as_ref().unwrap().clone() };
        
        #[cfg(feature = "test")]
        let inner_db = REGISTRY_DB.with(|registry_db| registry_db.borrow().clone().unwrap());
        
        let latest_id = if let Some(latest_id) = inner_db.db_ref.as_ref().unwrap().get(Self::LATEST_ID_KEY).unwrap() {
            decode_be_u64!(latest_id).unwrap()
        } else {
            inner_db.db_ref.as_ref().unwrap().put(Self::LATEST_ID_KEY, &[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            0
        };

        // TODO: When initializing the state registry,
        // delete all checkpoints which are not listed 
        // in the ids and heights entry.

        StateRegistry {
            latest_id,
            inner_db,
            working_dir,
        }
    }

    /// Returns the listed checkpoints ids and their corresponding heights
    pub fn retrieve_ids_and_heights(&self) -> Option<Vec<(u64, u64)>> {
        let ids_and_heights = self.inner_db.retrieve(Self::IDS_AND_HEIGHTS_KEY)?;
        let ids_and_heights = rlp::decode_list::<Vec<u8>>(&ids_and_heights);
        
        if ids_and_heights.is_empty() {
            return None;
        }
        
        let ids_and_heights = ids_and_heights
            .iter()
            .map(|encoded| {
                let mut cursor = Cursor::new(encoded);
                let id = cursor.read_u64::<BigEndian>().unwrap();
                let height = cursor.read_u64::<BigEndian>().unwrap();

                (id, height)
            })
            .collect();

        Some(ids_and_heights)
    }

    // TODO: Make this async
    pub fn delete_checkpoint(&mut self, id: u64) -> Result<(), ()> {
        let path = self.working_dir.join(&format!("{}", id));
        let exists = fs::metadata(&path).is_ok();

        if exists {
            let ids_and_heights = self
                .retrieve_ids_and_heights()
                .unwrap()
                .iter()
                // Remove entry with given id
                .filter(|(i, _)| *i != id)
                .cloned()
                .collect();

            let entries = Self::encode_ids_and_heights(ids_and_heights);
            
            // Update database entries
            self.inner_db.put(Self::IDS_AND_HEIGHTS_KEY, &entries);

            // Delete checkpoint dir
            fs::remove_dir_all(&path).unwrap();
            Ok(())
        } else {
            Err(())
        }
    }

    // TODO: Maybe return a `Result` instead of panicking.
    pub fn checkpoint(&mut self, db_ref: Arc<DB>, height: u64) -> u64 {
        let latest_id = if let Some(latest_id) = self.inner_db.retrieve(Self::LATEST_ID_KEY) {
            decode_be_u64!(latest_id).unwrap()
        } else {
            unreachable!();
        };

        let next_id = latest_id + 1;
        let checkpoint = Checkpoint::new(db_ref.as_ref()).unwrap();
        let checkpoint_path = self.working_dir.join(&format!("{}", next_id));
        checkpoint.create_checkpoint(checkpoint_path).unwrap();

        let ids_and_heights = self.retrieve_ids_and_heights();

        // Update ids and heights entry
        let entries: Vec<u8> = if let Some(mut ids_and_heights) = ids_and_heights {
            ids_and_heights.push((next_id, height));
            Self::encode_ids_and_heights(ids_and_heights)
        } else {
            // Create ids and heights entry if it doesn't exist
            Self::encode_ids_and_heights(vec![(next_id, height)])
        };

        // Write entries to db
        self.inner_db.put(Self::IDS_AND_HEIGHTS_KEY, &entries);

        // Write next id
        self.inner_db.put(Self::LATEST_ID_KEY, &encode_be_u64!(next_id));
        self.latest_id = next_id;

        next_id
    }

    fn encode_ids_and_heights(ids_and_heights: Vec<(u64, u64)>) -> Vec<u8> {
        let mut rlp = RlpStream::new_list(ids_and_heights.len());

        // Encode entries
        for (id, height) in ids_and_heights {
            let mut buf = Vec::with_capacity(16);
            let encoded_id = encode_be_u64!(id);
            let encoded_height = encode_be_u64!(height);

            buf.extend_from_slice(&encoded_id);
            buf.extend_from_slice(&encoded_height);

            rlp.append(&buf);
        }

        rlp.out()
    }
}