/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

#[macro_use]
extern crate bin_tools;
#[macro_use]
extern crate cfg_if;

use ansi_term::Colour::Green;
use rocksdb::DB;
use std::path::{Path, PathBuf};

pub fn open_database(path: &PathBuf, wal_path: &Path) -> DB {
    DB::open(&crate::db_options(wal_path), path.to_str().unwrap()).unwrap()
}

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate tempdir;
#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

pub use hasher::*;
pub use node_codec::*;
pub use persistent_db::*;

mod hasher;
mod node_codec;
mod persistent_db;
