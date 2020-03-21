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
use crate::downloader::sub_piece_info::{SubPieceInfo, SubPieceState};
use crypto::ShortHash;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct SubPiece {
    /// The checksum of the sub-piece
    pub(crate) checksum: ShortHash,

    /// The size of the sub-piece in bytes
    pub(crate) size: u64,

    /// Sub-piece data. This is `None` if we haven't downloaded the sub-piece.
    pub(crate) data: Option<Arc<Vec<u8>>>,
}

impl SubPiece {
    pub fn new(size: u64, checksum: ShortHash) -> Self {
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
        if data.len() as u64 != self.size {
            return Err(DownloaderErr::InvalidSize);
        }

        if self.data.is_some() {
            return Err(DownloaderErr::AlreadyHaveData);
        }

        let checksum = crypto::hash_slice(&data).to_short();

        if checksum != self.checksum {
            return Err(DownloaderErr::InvalidChecksum);
        }

        self.data = Some(data.clone());
        Ok(())
    }

    pub fn to_info(&self) -> SubPieceInfo {
        let state = if self.data.is_some() {
            SubPieceState::Downloaded
        } else {
            SubPieceState::Pending
        };

        SubPieceInfo::new(self.size, self.checksum, state)
    }
}

impl From<&SubPieceInfo> for SubPiece {
    fn from(info: &SubPieceInfo) -> Self {
        SubPiece::new(info.size, info.checksum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds_data() {
        let data = b"data".to_vec();
        let checksum = crypto::hash_slice(&data).to_short();
        let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
        sub_piece.add_data(Arc::new(data.clone())).unwrap();
        assert_eq!(sub_piece.data, Some(Arc::new(data.clone())));
        assert!(sub_piece.is_done());
    }

    #[test]
    fn it_fails_adding_data_bad_checksum() {
        let data = b"data".to_vec();
        let checksum = crypto::hash_slice(b"other_data").to_short();
        let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
        assert_eq!(sub_piece.add_data(Arc::new(data.clone())), Err(DownloaderErr::InvalidChecksum));
    }

    #[test]
    fn to_info() {
        let data = b"data".to_vec();
        let checksum = crypto::hash_slice(&data).to_short();
        let oracle_info = SubPieceInfo::new(data.len() as u64, checksum, SubPieceState::Downloaded);
        let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
        sub_piece.add_data(Arc::new(data.clone())).unwrap();
        assert_eq!(sub_piece.to_info(), oracle_info);
    }
}