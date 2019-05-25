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

  This is a modified version of the following file: 
  https://github.com/mimblewimble/grin-miner/blob/master/cuckoo-miner/src/build.rs
*/

// Only compile miner code if `cpu` or `gpu` features are set

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod ffi;

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod plugin;

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod error;

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod plugin_config;

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod shared_data;

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod solver_instance;

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod miner;

#[cfg(any(feature = "cpu", feature = "gpu"))]
mod proof;

#[cfg(any(feature = "cpu", feature = "gpu"))]
pub use crate::miner::*;