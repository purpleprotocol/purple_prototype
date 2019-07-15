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
use std::sync::Arc;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

// Use thread_local on `cfg(test)`.
cfg_if! {
    if #[cfg(feature = "test")] {
        use std::cell::RefCell;

        thread_local! {
            static INITIALIZED: RefCell<bool> = RefCell::new(false);

            /// Directory containing checkpoints
            pub(crate) static WORKING_DIR: RefCell<Option<PathBuf>> = RefCell::new(None);

            /// Internal database
            pub(crate) static REGISTRY_DB: RefCell<Option<PersistentDb>> = RefCell::new(None);
        }
    } else {
        static INITIALIZED: AtomicBool = AtomicBool::new(false);

        /// Directory containing checkpoints
        pub(crate) static mut WORKING_DIR: Option<PathBuf> = None;

        /// Internal database
        pub(crate) static mut REGISTRY_DB: Option<PersistentDb> = None;
    }
}

/// This function must be called in `fn main()` at the beginning
/// in order to initialize database paths. Note that this function
/// **IS NOT** thread-safe.
#[cfg(not(feature = "test"))]
pub fn init(working_dir: PathBuf) {
    if INITIALIZED.load(Ordering::Relaxed) {
        panic!("Already called init! This function can only be called once!");
    }

    unsafe {
        let registry_db_path = working_dir.join("registry_db");
        let registry_db = crate::open_database_no_checks(&registry_db_path);
        let registry_db = PersistentDb::new_without_checks(Arc::new(registry_db), None);

        // Set registry db
        REGISTRY_DB = Some(registry_db);

        // Set working dir
        WORKING_DIR = Some(working_dir);
    }

    // Flag as initialized
    INITIALIZED.store(true, Ordering::Relaxed);
}

#[cfg(feature = "test")]
pub fn init(working_dir: PathBuf) {
    if !is_initialized() {
        // Set initialized flag
        INITIALIZED.with(|initialized| {
            let mut initialized = initialized.borrow_mut();
            *initialized = true;
        });
    } else {
        panic!("Already called init! This function can only be called once!");
    }

    let registry_db_path = working_dir.join("registry_db");
    let registry_db = crate::open_database_no_checks(&registry_db_path);
    let registry_db = PersistentDb::new_without_checks(Arc::new(registry_db), None);

    // Set registry db
    REGISTRY_DB.with(|db_ref| {
        *db_ref.borrow_mut() = Some(registry_db);
    });

    // Set working dir
    WORKING_DIR.with(|dir_ref| {
        *dir_ref.borrow_mut() = Some(working_dir);
    });
}

/// Returns `true` if the persistence module is initialized
#[cfg(not(feature = "test"))]
pub fn is_initialized() -> bool {
    unsafe {
        INITIALIZED.load(Ordering::Relaxed) && WORKING_DIR.is_some() && REGISTRY_DB.is_some()
    }
}

#[cfg(feature = "test")]
pub fn is_initialized() -> bool {
    INITIALIZED.with(|initialized| {
        initialized.borrow().clone()
    })
}