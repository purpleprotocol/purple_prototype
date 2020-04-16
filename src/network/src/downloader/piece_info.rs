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

use crate::downloader::sub_piece_info::SubPieceInfo;
use crypto::ShortHash;
use constants::*;

#[derive(Debug, Clone, PartialEq)]
pub struct PieceInfo {
    /// The size of the piece
    pub(crate) size: u64,

    /// Amount of bytes already downloaded
    pub(crate) completed: u64,

    /// Checksum of the piece
    pub(crate) checksum: ShortHash,

    /// Sub-pieces info
    pub(crate) sub_pieces: Option<Vec<SubPieceInfo>>,
}

impl PieceInfo {
    pub fn new(size: u64, checksum: ShortHash, sub_pieces: Option<Vec<SubPieceInfo>>) -> Self {
        let completed = if let Some(sub_pieces) = sub_pieces.as_ref() {
            if sub_pieces.len() == 0 {
                panic!("Cannot create PieceInfo from an empty vector!");
            }

            let mut completed = 0;

            for sub_piece in sub_pieces.iter() {
                if sub_piece.is_complete() {
                    completed += sub_piece.size;
                }
            }

            completed
        } else {
            0
        };

        if size > MAX_PIECE_SIZE as u64 {
            panic!("Cannot crate PieceInfo with a sum of all SubPieces sizes greater than {}! Got: {}", MAX_PIECE_SIZE, size);
        }
        
        PieceInfo { checksum, sub_pieces, size, completed }
    }
}