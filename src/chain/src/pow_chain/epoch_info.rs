/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

use hashbrown::HashSet;
use crypto::NodeId;

#[derive(Clone, Debug, PartialEq)]
pub struct EpochInfo {
    /// Current epoch
    pub(crate) epoch: u64,

    /// Set containing node ids that should join the pool in this epoch.
    pub(crate) should_join: HashSet<NodeId>,

    /// Set containing node ids that should remain in the pool in this epoch
    /// i.e. not join nor leave the pool.
    pub(crate) should_remain: HashSet<NodeId>,

    /// Set containing node ids that should leave the pool at the end of this epoch.
    pub(crate) should_leave: HashSet<NodeId>,
}