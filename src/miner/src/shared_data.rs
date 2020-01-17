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

use crate::plugin::{SolverSolutions, SolverStats};

/// Data intended to be shared across threads
pub struct JobData {
    /// ID of the current running job (not currently used)
    pub job_id: u32,

    /// block height of current running job
    pub height: u64,

    /// Header
    pub header: Vec<u8>,

    /// The target difficulty. Only solutions >= this
    /// target will be put into the output queue
    pub difficulty: u64,

    /// Output solutions
    pub solutions: Vec<SolverSolutions>,

    /// Current stats
    pub stats: Vec<SolverStats>,
}

impl Default for JobData {
    fn default() -> JobData {
        JobData {
            job_id: 0,
            height: 0,
            header: Vec::new(),
            difficulty: 0,
            solutions: Vec::new(),
            stats: vec![],
        }
    }
}

impl JobData {
    pub fn new(num_solvers: usize) -> JobData {
        JobData {
            job_id: 0,
            height: 0,
            header: Vec::new(),
            difficulty: 1,
            solutions: Vec::new(),
            stats: vec![SolverStats::default(); num_solvers],
        }
    }
}
