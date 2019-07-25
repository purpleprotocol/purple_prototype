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

#[macro_use] extern crate bin_tools;
#[macro_use] extern crate cfg_if;

extern crate byteorder;
extern crate ansi_term;

use ansi_term::Colour::Green;
use std::path::{Path, PathBuf};
use rocksdb::DB;

pub fn open_database(path: &PathBuf, wal_path: &Path) -> DB {
    DB::open(&crate::db_options(wal_path), path.to_str().unwrap()).unwrap()
}

#[cfg(test)]
extern crate tempdir;
#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

extern crate crypto;
extern crate elastic_array;
extern crate hashbrown;
extern crate hashdb;
extern crate num_cpus;
extern crate parking_lot;
extern crate patricia_trie;
extern crate rlp;
extern crate rocksdb;

pub use hasher::*;
pub use node_codec::*;
pub use persistent_db::*;

mod hasher;
mod node_codec;
mod persistent_db;