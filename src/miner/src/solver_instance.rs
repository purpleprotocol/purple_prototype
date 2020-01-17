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

  Parts of this file were adapted from the following file:
  https://github.com/mimblewimble/grin-miner/blob/master/cuckoo-miner/src/miner/types.rs
*/

use crate::error::CuckooMinerError;
use crate::ffi::PluginLibrary;
use crate::plugin::{SolverSolutions, SolverStats};
use crate::plugin_config::PluginConfig;

/// Holds a loaded lib + config + stats
/// 1 instance = 1 device on 1 controlling thread
pub struct SolverInstance {
    /// The loaded plugin
    pub lib: PluginLibrary,
    /// Associated config
    pub config: PluginConfig,
    /// Last stats output
    pub stats: SolverStats,
    /// Last solution output
    pub solutions: SolverSolutions,
}

impl SolverInstance {
    /// Create a new solver instance with the given config
    pub fn new(config: PluginConfig) -> Result<SolverInstance, CuckooMinerError> {
        let l = PluginLibrary::new(&config.file)?;
        Ok(SolverInstance {
            lib: l,
            config: config,
            stats: SolverStats::default(),
            solutions: SolverSolutions::default(),
        })
    }

    /// Release the lib
    pub fn unload(&mut self) {
        self.lib.unload();
    }
}
