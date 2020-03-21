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

use crypto::ShortHash;

#[derive(Clone, Debug, PartialEq)]
pub struct SubPieceInfo {
    /// The checksum of the sub-piece
    pub(crate) checksum: ShortHash,

    /// The size of the sub-piece in bytes
    pub(crate) size: u64,

    /// The download state of the `SubPiece`
    pub(crate) state: SubPieceState,
}

impl SubPieceInfo {
    pub fn new(size: u64, checksum: ShortHash, state: SubPieceState) -> SubPieceInfo {
        SubPieceInfo {
            checksum,
            size,
            state,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == SubPieceState::Downloaded
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SubPieceState {
    /// We have downloaded the `SubPiece`
    Downloaded,

    /// We have not downloaded the `SubPiece`
    Pending,
}