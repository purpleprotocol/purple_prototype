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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static mut WORKING_DIR: Option<PathBuf> = None;

/// This function must be called in `fn main()` at the beginning
/// in order to initialize database paths. Note that this function
/// **IS NOT** thread-safe.
pub fn init(working_dir: PathBuf) {
    unsafe {
        // Set working dir
        WORKING_DIR = Some(working_dir);
    }

    // Flag as initialized
    INITIALIZED.store(true, Ordering::Relaxed);
}

/// Returns `true` if the persistence module is initialized
pub fn is_initialized() -> bool {
    unsafe {
        INITIALIZED.load(Ordering::Relaxed) && WORKING_DIR.is_some()
    }
}