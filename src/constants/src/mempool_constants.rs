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

/// The threshold value after which the prune happens (percentage)
/// 
/// Remark: Must be between 50 and 100
pub const PRUNE_THRESHOLD: u32 = 80;

/// How far into the future a transaction can be
/// in order to be accepted.
pub const FUTURE_LIMIT: u64 = 10;

static_assertions::const_assert!(crate::PRUNE_THRESHOLD > 50);
static_assertions::const_assert!(crate::PRUNE_THRESHOLD < 100);