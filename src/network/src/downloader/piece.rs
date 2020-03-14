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

use crate::downloader::error::DownloaderErr;
use crate::downloader::sub_piece::SubPiece;
use crate::downloader::piece_info::PieceInfo;
use crypto::ShortHash;

#[derive(Debug)]
pub struct Piece {
    /// The size of the piece in bytes
    pub(crate) size: u64,

    /// Number of bytes downloaded
    pub(crate) downloaded: u64,

    /// The blake3 checksum of the piece
    pub(crate) checksum: ShortHash,

    /// Sub-pieces of the piece. This is `None` if we don't have info
    /// about the piece.
    pub(crate) sub_pieces: Option<Vec<SubPiece>>

}

impl Piece {
    /// Returns `true` if we have info about this piece's sub-pieces.
    pub fn has_info(&self) -> bool {
        self.sub_pieces.is_some()
    }

    /// Adds info to the piece, verifying the checksum of the 
    /// given sub-pieces. Returns `Err(_)` if we already have info
    /// or if the checksum validation failed.
    pub fn add_info(&self, info: &PieceInfo) -> Result<(), DownloaderErr> {
        unimplemented!();
    }
}