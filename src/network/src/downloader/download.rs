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
use crate::downloader::download_info::DownloadInfo;
use crate::downloader::download_state::DownloadState;
use crate::downloader::piece::Piece;
use chain::{MAX_PIECE_SIZE, MAX_TX_SET_SIZE};
use hashbrown::HashMap;
use chrono::*;
use crypto::ShortHash;
use std::sync::Arc;

#[derive(Debug, PartialEq)]
pub struct Download {
    /// The size of the download in bytes
    pub(crate) size: u64,

    /// Completed bytes
    pub(crate) completed: u64,

    /// The priority of the download
    pub(crate) priority: u64,

    /// When the download was created
    pub(crate) created_at: DateTime<Utc>,

    /// The state of the download
    pub(crate) state: DownloadState,

    /// Pieces of the download
    pub(crate) pieces: Vec<Piece>,

    /// Mapping between piece checksums and index 
    checksum_mappings: HashMap<ShortHash, usize>,
}

impl Download {
    pub fn from_pieces(size: u64, pieces: Vec<Piece>, priority: u64) -> Result<Self, DownloaderErr> {
        unimplemented!();
    }

    pub fn from_checksums_and_sizes(checksums: &[(ShortHash, u64)], priority: u64) -> Result<Self, DownloaderErr> {
        if checksums.len() == 0 || checksums.len() > MAX_TX_SET_SIZE / MAX_PIECE_SIZE {
            return Err(DownloaderErr::InvalidSize);
        }
        
        let mut size = 0;
        let mut pieces = Vec::with_capacity(checksums.len());
        let mut checksum_mappings = HashMap::with_capacity(checksums.len());

        for (i, (checksum, piece_size)) in checksums.iter().enumerate() {
            if *piece_size > MAX_PIECE_SIZE as u64 || *piece_size == 0 {
                return Err(DownloaderErr::InvalidSize);
            }

            if checksum_mappings.get(checksum).is_some() {
                return Err(DownloaderErr::DuplicateChecksum);
            }

            let piece = Piece::new(*piece_size, *checksum);
            pieces.push(piece);
            checksum_mappings.insert(*checksum, i);
            size += *piece_size
        }

        if size > MAX_TX_SET_SIZE as u64 {
            return Err(DownloaderErr::InvalidSize);
        }

        let download = Download {
            size,
            pieces,
            checksum_mappings,
            priority,
            state: DownloadState::NotStarted,
            completed: 0,
            created_at: Utc::now(),
        };

        Ok(download)
    }

    pub fn to_info(&self) -> DownloadInfo {
        unimplemented!();
    }

    pub fn append_raw_sub_piece(&mut self, piece: &ShortHash, sub_piece: &ShortHash, raw: Arc<Vec<u8>>) -> Result<(), DownloaderErr> {
        unimplemented!();
    }

    pub fn is_not_started(&self) -> bool {
        self.state == DownloadState::NotStarted
    }

    pub fn is_pending(&self) -> bool {
        self.state == DownloadState::NotStarted || self.state == DownloadState::Downloading
    }

    pub fn is_complete(&self) -> bool {
        self.state == DownloadState::Completed
    }

    pub fn is_paused(&self) -> bool {
        self.state == DownloadState::Paused
    }

    pub fn is_queued(&self) -> bool {
        self.state == DownloadState::Queued
    }

    pub fn state(&self) -> DownloadState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_checksums_and_sizes() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_4").to_short(), 345),
        ];

        let download = Download::from_checksums_and_sizes(&checksums, 0).unwrap();

        assert_eq!(download.pieces.len(), checksums.len());
        assert_eq!(download.checksum_mappings.len(), checksums.len());
        assert!(download.is_not_started());

        for (i, (checksum, size)) in checksums.iter().enumerate() {
            let piece = &download.pieces[i];
            assert_eq!(&piece.checksum, checksum);
            assert_eq!(piece.size, *size);
            assert_eq!(piece.downloaded, 0);
            assert_eq!(download.checksum_mappings.get(checksum), Some(&i));
            assert!(piece.sub_pieces.is_none());
        }
    }

    #[test]
    fn from_checksums_and_sizes_fails_on_invalid_size() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_4").to_short(), (MAX_PIECE_SIZE as u64) + 1),
        ];

        let download = Download::from_checksums_and_sizes(&checksums, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn from_checksums_and_sizes_fails_on_0_pieces() {
        let checksums = vec![];

        let download = Download::from_checksums_and_sizes(&checksums, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn from_checksums_and_sizes_fails_on_greater_piece_count() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_4").to_short(), 100345),
            (crypto::hash_slice(b"checksum_5").to_short(), 100345),
            (crypto::hash_slice(b"checksum_6").to_short(), 100345),
            (crypto::hash_slice(b"checksum_7").to_short(), 100345),
            (crypto::hash_slice(b"checksum_8").to_short(), 100345),
            (crypto::hash_slice(b"checksum_9").to_short(), 100345),
            (crypto::hash_slice(b"checksum_10").to_short(), 100345),
            (crypto::hash_slice(b"checksum_11").to_short(), 100345),
            (crypto::hash_slice(b"checksum_12").to_short(), 100345),
        ];

        let download = Download::from_checksums_and_sizes(&checksums, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn from_checksums_fails_on_duplicate_checksum() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_3").to_short(), 345),
        ];

        let download = Download::from_checksums_and_sizes(&checksums, 0);
        assert_eq!(download, Err(DownloaderErr::DuplicateChecksum));
    }

    #[test]
    fn from_checksums_fails_on_0_piece_size() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_4").to_short(), 0),
        ];

        let download = Download::from_checksums_and_sizes(&checksums, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn from_pieces() {
        assert!(false);
    }

    #[test]
    fn to_info() {
        assert!(false);
    }

    #[test]
    fn append_raw_sub_piece() {
        assert!(false);
    }

    #[test]
    fn append_raw_sub_piece_fails_invalid_piece() {
        assert!(false);
    }

    #[test]
    fn append_raw_sub_piece_fails_invalid_sub_piece() {
        assert!(false);
    }

    #[test]
    fn append_raw_sub_piece_fails_invalid_checksum() {
        assert!(false);
    }
}