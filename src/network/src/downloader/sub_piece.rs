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
use crate::downloader::sub_piece_info::SubPieceInfo;
use crypto::ShortHash;
use std::sync::Arc;

#[derive(Debug)]
pub struct SubPiece {
    /// The checksum of the sub-piece
    pub(crate) checksum: ShortHash,

    /// The size of the sub-piece in bytes
    pub(crate) size: usize,

    /// Sub-piece data. This is `None` if we haven't downloaded the sub-piece.
    pub(crate) data: Option<Arc<Vec<u8>>>,
}

impl SubPiece {
    pub fn new(size: usize, checksum: ShortHash) -> Self {
        SubPiece {
            size,
            checksum,
            data: None,
        }
    }

    /// Returns `true` if the sub-piece has been downloaded
    pub fn is_done(&self) -> bool {
        self.data.is_some()
    }

    pub fn add_data(&mut self, data: Arc<Vec<u8>>) -> Result<(), DownloaderErr> {
        if data.len() != self.size {
            return Err(DownloaderErr::InvalidSize);
        }

        let checksum = crypto::hash_slice(&data).to_short();

        if checksum != self.checksum {
            return Err(DownloaderErr::InvalidChecksum);
        }

        self.data = Some(data.clone());
        Ok(())
    }
}

impl From<&SubPieceInfo> for SubPiece {
    fn from(info: &SubPieceInfo) -> Self {
        SubPiece::new(info.size, info.checksum)
    }
}