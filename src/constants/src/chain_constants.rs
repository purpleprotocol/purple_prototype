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

/// The maximum size, in bytes, of a transaction set in a transaction block.
pub const MAX_TX_SET_SIZE: usize = 2097152; // 2mb

/// The maximum allowed size of a piece of transactions. `MAX_TX_SET_SIZE % MAX_PIECE_SIZE` must equal to 0
pub const MAX_PIECE_SIZE: usize = 262144; // 256kb

/// The maximum allowed size of a sub-piece. `MAX_PIECE_SIZE % MAX_SUB_PIECE_SIZE` must equal to 0
pub const MAX_SUB_PIECE_SIZE: usize = 16384; // 16kb

static_assertions::const_assert_eq!(crate::MAX_TX_SET_SIZE % crate::MAX_PIECE_SIZE, 0);
static_assertions::const_assert_eq!(crate::MAX_PIECE_SIZE % crate::MAX_SUB_PIECE_SIZE, 0);