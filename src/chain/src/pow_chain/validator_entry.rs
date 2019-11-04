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

use std::net::SocketAddr;
use crypto::Hash;

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatorEntry {
    /// The ip of the validator
    pub ip: SocketAddr,

    /// The hash of the mined pow block by the validator
    pub start_pow_block: Hash,

    /// Total allocated events for this validator.
    pub total_allocated: u64,
}

impl ValidatorEntry {
    pub fn new(ip: SocketAddr, start_pow_block: Hash, total_allocated: u64) -> ValidatorEntry {
        ValidatorEntry {
            ip,
            start_pow_block,
            total_allocated,
        }
    }
}