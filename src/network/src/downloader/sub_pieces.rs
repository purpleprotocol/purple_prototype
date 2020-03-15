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
use crypto::ShortHash;
use hashbrown::HashMap;
use std::sync::Arc;

/// A set of sub-pieces
#[derive(Debug)]
pub struct SubPieces {
    /// Sub-pieces list 
    pub(crate) sub_pieces: Vec<SubPiece>,
    
    /// Mapping between a sub-piece hash and its index
    pub(crate) index_mappings: HashMap<ShortHash, usize>,
}

impl SubPieces {
    pub fn new(sub_pieces: Vec<SubPiece>) -> Self {
        let mut index_mappings: HashMap<ShortHash, usize> = HashMap::with_capacity(sub_pieces.len());
        
        for (i, sub_piece) in sub_pieces.iter().enumerate() {
            index_mappings.insert(sub_piece.checksum, i);
        }

        SubPieces {
            sub_pieces,
            index_mappings,
        }
    }

    pub fn add_data(&mut self, hash: &ShortHash, data: Arc<Vec<u8>>) -> Result<(), DownloaderErr> {
        let i = self.index_mappings.get(hash).ok_or(DownloaderErr::NotFound)?;
        let sub_piece = &mut self.sub_pieces[*i];
        sub_piece.add_data(data)?;

        Ok(())
    }
}