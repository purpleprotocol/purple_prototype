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

use crate::downloader::download_info::{DownloadInfo, DownloadType};
use crate::downloader::download_state::DownloadState;
use crate::downloader::error::DownloaderErr;
use crate::downloader::piece::Piece;
use crate::downloader::piece_info::PieceInfo;
use crate::downloader::sub_piece_info::SubPieceInfo;
use chrono::*;
use constants::*;
use crypto::ShortHash;
use hashbrown::HashMap;
use triomphe::Arc;

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
    pub fn from_pieces(pieces: Vec<Piece>, priority: u64) -> Result<Self, DownloaderErr> {
        if pieces.len() == 0 || pieces.len() > MAX_TX_SET_SIZE / MAX_PIECE_SIZE {
            return Err(DownloaderErr::InvalidSize);
        }

        let mut size = 0;
        let mut checksum_mappings = HashMap::with_capacity(pieces.len());

        for (i, piece) in pieces.iter().enumerate() {
            let piece_size = &piece.size;
            let checksum = &piece.checksum;

            if *piece_size > MAX_PIECE_SIZE as u64 || *piece_size == 0 {
                return Err(DownloaderErr::InvalidSize);
            }

            if checksum_mappings.get(checksum).is_some() {
                return Err(DownloaderErr::DuplicateChecksum);
            }

            checksum_mappings.insert(*checksum, i);
            size += *piece_size;
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

    pub fn from_checksums_and_sizes(
        checksums: &[(ShortHash, u64)],
        priority: u64,
    ) -> Result<Self, DownloaderErr> {
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
            size += *piece_size;
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
        let pieces = self.pieces.iter().map(|p| p.to_info()).collect();

        DownloadInfo {
            size: self.size,
            completed: self.completed,
            created_at: self.created_at,
            priority: self.priority,
            state: self.state,
            download_type: DownloadType::Block,
            pieces,
        }
    }

    pub fn add_info(&mut self, piece: &ShortHash, info: &PieceInfo) -> Result<(), DownloaderErr> {
        let piece_i = self
            .checksum_mappings
            .get(piece)
            .ok_or(DownloaderErr::NotFound)?;
        let mut piece = &mut self.pieces[*piece_i];
        piece.add_info(info)
    }

    /// This panics if we don't have info about a `Piece`
    pub fn append_raw_sub_piece(
        &mut self,
        piece: &ShortHash,
        sub_piece: &ShortHash,
        raw: Arc<Vec<u8>>,
    ) -> Result<(), DownloaderErr> {
        let piece_i = self
            .checksum_mappings
            .get(piece)
            .ok_or(DownloaderErr::NotFound)?;
        let mut piece = &mut self.pieces[*piece_i];

        piece
            .sub_pieces
            .as_mut()
            .unwrap()
            .add_data(sub_piece, raw.clone())?;

        // Mark as started if this is the first appended piece
        if let DownloadState::NotStarted = self.state {
            self.state = DownloadState::Downloading;
        }

        self.completed += raw.len() as u64;

        // Mark as complete if this is the last sub-piece
        if self.completed == self.size {
            self.state = DownloadState::Completed;
        }

        Ok(())
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
    use crate::downloader::download_info::DownloadType;
    use crate::downloader::piece_info::PieceInfo;
    use crate::downloader::sub_piece_info::SubPieceState;
    use rand::prelude::*;

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
            assert_eq!(piece.completed, 0);
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
            (
                crypto::hash_slice(b"checksum_4").to_short(),
                (MAX_PIECE_SIZE as u64) + 1,
            ),
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
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_4").to_short(), 345),
        ];

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size)| Piece::new(*size, *checksum))
            .collect();

        let download = Download::from_pieces(pieces, 0).unwrap();

        assert_eq!(download.pieces.len(), checksums.len());
        assert_eq!(download.checksum_mappings.len(), checksums.len());
        assert!(download.is_not_started());

        for (i, (checksum, size)) in checksums.iter().enumerate() {
            let piece = &download.pieces[i];
            assert_eq!(&piece.checksum, checksum);
            assert_eq!(piece.size, *size);
            assert_eq!(piece.completed, 0);
            assert_eq!(download.checksum_mappings.get(checksum), Some(&i));
            assert!(piece.sub_pieces.is_none());
        }
    }

    #[test]
    fn from_pieces_fails_on_invalid_size() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (
                crypto::hash_slice(b"checksum_4").to_short(),
                (MAX_PIECE_SIZE as u64) + 1,
            ),
        ];

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size)| Piece::new(*size, *checksum))
            .collect();

        let download = Download::from_pieces(pieces, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn from_pieces_and_sizes_fails_on_0_pieces() {
        let pieces = vec![];
        let download = Download::from_pieces(pieces, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn from_pieces_fails_on_greater_piece_count() {
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

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size)| Piece::new(*size, *checksum))
            .collect();

        let download = Download::from_pieces(pieces, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn from_pieces_fails_on_duplicate_checksum() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_3").to_short(), 345),
        ];

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size)| Piece::new(*size, *checksum))
            .collect();

        let download = Download::from_pieces(pieces, 0);
        assert_eq!(download, Err(DownloaderErr::DuplicateChecksum));
    }

    #[test]
    fn from_pieces_fails_on_0_piece_size() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_4").to_short(), 0),
        ];

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size)| Piece::new(*size, *checksum))
            .collect();

        let download = Download::from_pieces(pieces, 0);
        assert_eq!(download, Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn to_info() {
        let checksums = vec![
            (crypto::hash_slice(b"checksum_1").to_short(), 200345),
            (crypto::hash_slice(b"checksum_2").to_short(), 220345),
            (crypto::hash_slice(b"checksum_3").to_short(), 100345),
            (crypto::hash_slice(b"checksum_4").to_short(), 345),
        ];

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size)| Piece::new(*size, *checksum))
            .collect();

        let infos: Vec<PieceInfo> = pieces.iter().map(|p| p.to_info()).collect();

        let download = Download::from_pieces(pieces, 0).unwrap();
        let info = download.to_info();

        assert_eq!(info.size, download.size);
        assert_eq!(info.completed, download.completed);
        assert_eq!(info.priority, download.priority);
        assert_eq!(info.created_at, download.created_at);
        assert_eq!(info.state, download.state);
        assert_eq!(info.download_type, DownloadType::Block);
        assert_eq!(info.pieces.len(), infos.len());

        for (i, piece) in download.pieces.iter().enumerate() {
            let info = &infos[i];
            assert_eq!(info.size, piece.size);
            assert_eq!(info.checksum, piece.checksum);
            // let sub_pieces = info.sub_pieces.as_ref().unwrap();

            // for (i, sub_piece) in sub_pieces.iter().enumerate() {
            //     let info = &sub_pieces[i];
            //     assert_eq!(info.size, sub_piece.size);
            //     assert_eq!(info.checksum, sub_piece.checksum);
            //     assert_eq!(info.state, SubPieceState::Pending);
            // }
        }
    }

    #[test]
    fn append_raw_sub_piece() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
            b"data5".to_vec(),
        ];

        let checksums: Vec<_> = data
            .iter()
            .map(|d| (crypto::hash_slice(&d).to_short(), d.len() as u64, d.clone()))
            .collect();

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size, data)| {
                (
                    data,
                    Piece::new(*size, crypto::hash_slice(&checksum.0).to_short()),
                )
            })
            .map(|(data, mut piece)| {
                let checksum = crypto::hash_slice(&data).to_short();
                let infos = vec![SubPieceInfo::new(
                    data.len() as u64,
                    checksum,
                    SubPieceState::Pending,
                )];
                let info = PieceInfo::new(
                    data.len() as u64,
                    crypto::hash_slice(&checksum.0).to_short(),
                    Some(infos),
                );
                piece.add_info(&info).unwrap();
                piece
            })
            .collect();

        let mut download = Download::from_pieces(pieces, 0).unwrap();
        assert!(download.is_not_started());

        for (checksum, _, data) in checksums.iter() {
            let piece_checksum = crypto::hash_slice(&checksum.0).to_short();
            download
                .append_raw_sub_piece(&piece_checksum, checksum, Arc::new(data.clone()))
                .unwrap();
            assert!(download.is_pending() || download.is_complete());
        }

        assert!(download.is_complete());
    }

    #[test]
    fn append_raw_sub_piece_fails_invalid_piece() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
            b"data5".to_vec(),
        ];

        let checksums: Vec<_> = data
            .iter()
            .map(|d| (crypto::hash_slice(&d).to_short(), d.len() as u64, d.clone()))
            .collect();

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size, data)| {
                (
                    data,
                    Piece::new(*size, crypto::hash_slice(&checksum.0).to_short()),
                )
            })
            .map(|(data, mut piece)| {
                let checksum = crypto::hash_slice(&data).to_short();
                let infos = vec![SubPieceInfo::new(
                    data.len() as u64,
                    checksum,
                    SubPieceState::Pending,
                )];
                let info = PieceInfo::new(
                    data.len() as u64,
                    crypto::hash_slice(&checksum.0).to_short(),
                    Some(infos),
                );
                piece.add_info(&info).unwrap();
                piece
            })
            .collect();

        let mut download = Download::from_pieces(pieces, 0).unwrap();
        assert!(download.is_not_started());

        for (checksum, _, data) in checksums.iter() {
            let piece_checksum = crypto::hash_slice(b"random").to_short();
            assert_eq!(
                download.append_raw_sub_piece(&piece_checksum, checksum, Arc::new(data.clone())),
                Err(DownloaderErr::NotFound)
            );
        }
    }

    #[test]
    fn append_raw_sub_piece_fails_invalid_sub_piece() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
            b"data5".to_vec(),
        ];

        let checksums: Vec<_> = data
            .iter()
            .map(|d| (crypto::hash_slice(&d).to_short(), d.len() as u64, d.clone()))
            .collect();

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size, data)| {
                (
                    data,
                    Piece::new(*size, crypto::hash_slice(&checksum.0).to_short()),
                )
            })
            .map(|(data, mut piece)| {
                let checksum = crypto::hash_slice(&data).to_short();
                let infos = vec![SubPieceInfo::new(
                    data.len() as u64,
                    checksum,
                    SubPieceState::Pending,
                )];
                let info = PieceInfo::new(
                    data.len() as u64,
                    crypto::hash_slice(&checksum.0).to_short(),
                    Some(infos),
                );
                piece.add_info(&info).unwrap();
                piece
            })
            .collect();

        let mut download = Download::from_pieces(pieces, 0).unwrap();
        assert!(download.is_not_started());

        for (checksum, _, data) in checksums.iter() {
            let piece_checksum = crypto::hash_slice(&checksum.0).to_short();
            let checksum = crypto::hash_slice(b"random").to_short();
            assert_eq!(
                download.append_raw_sub_piece(&piece_checksum, &checksum, Arc::new(data.clone())),
                Err(DownloaderErr::NotFound)
            );
        }
    }

    #[test]
    fn append_raw_sub_piece_fails_invalid_checksum() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
            b"data5".to_vec(),
        ];

        let checksums: Vec<_> = data
            .iter()
            .map(|d| (crypto::hash_slice(&d).to_short(), d.len() as u64, d.clone()))
            .collect();

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size, data)| {
                (
                    data,
                    Piece::new(*size, crypto::hash_slice(&checksum.0).to_short()),
                )
            })
            .map(|(data, mut piece)| {
                let checksum = crypto::hash_slice(&data).to_short();
                let infos = vec![SubPieceInfo::new(
                    data.len() as u64,
                    checksum,
                    SubPieceState::Pending,
                )];
                let info = PieceInfo::new(
                    data.len() as u64,
                    crypto::hash_slice(&checksum.0).to_short(),
                    Some(infos),
                );
                piece.add_info(&info).unwrap();
                piece
            })
            .collect();

        let mut download = Download::from_pieces(pieces, 0).unwrap();
        assert!(download.is_not_started());

        for (checksum, _, _) in checksums.iter() {
            let data = b"random".to_vec();
            let piece_checksum = crypto::hash_slice(&checksum.0).to_short();
            assert!(download
                .append_raw_sub_piece(&piece_checksum, checksum, Arc::new(data.clone()))
                .is_err());
        }
    }

    #[test]
    fn append_raw_sub_piece_fails_invalid_sub_piece_size() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
            b"data5".to_vec(),
        ];

        let checksums: Vec<_> = data
            .iter()
            .map(|d| (crypto::hash_slice(&d).to_short(), d.len() as u64, d.clone()))
            .collect();

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size, data)| {
                (
                    data,
                    Piece::new(*size, crypto::hash_slice(&checksum.0).to_short()),
                )
            })
            .map(|(data, mut piece)| {
                let checksum = crypto::hash_slice(&data).to_short();
                let infos = vec![SubPieceInfo::new(
                    data.len() as u64,
                    checksum,
                    SubPieceState::Pending,
                )];
                let info = PieceInfo::new(
                    data.len() as u64,
                    crypto::hash_slice(&checksum.0).to_short(),
                    Some(infos),
                );
                piece.add_info(&info).unwrap();
                piece
            })
            .collect();

        let mut download = Download::from_pieces(pieces, 0).unwrap();
        assert!(download.is_not_started());

        for (checksum, _, _) in checksums.iter() {
            let data = gen_random_bytes(MAX_SUB_PIECE_SIZE + 1);
            let piece_checksum = crypto::hash_slice(&checksum.0).to_short();
            assert_eq!(
                download.append_raw_sub_piece(&piece_checksum, checksum, Arc::new(data.clone())),
                Err(DownloaderErr::InvalidSize)
            );
        }
    }

    #[test]
    fn append_raw_sub_piece_fails_0_sub_piece_size() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
            b"data5".to_vec(),
        ];

        let checksums: Vec<_> = data
            .iter()
            .map(|d| (crypto::hash_slice(&d).to_short(), d.len() as u64, d.clone()))
            .collect();

        let pieces: Vec<Piece> = checksums
            .iter()
            .map(|(checksum, size, data)| {
                (
                    data,
                    Piece::new(*size, crypto::hash_slice(&checksum.0).to_short()),
                )
            })
            .map(|(data, mut piece)| {
                let checksum = crypto::hash_slice(&data).to_short();
                let infos = vec![SubPieceInfo::new(
                    data.len() as u64,
                    checksum,
                    SubPieceState::Pending,
                )];
                let info = PieceInfo::new(
                    data.len() as u64,
                    crypto::hash_slice(&checksum.0).to_short(),
                    Some(infos),
                );
                piece.add_info(&info).unwrap();
                piece
            })
            .collect();

        let mut download = Download::from_pieces(pieces, 0).unwrap();
        assert!(download.is_not_started());

        for (checksum, _, data) in checksums.iter() {
            let data = vec![];
            let piece_checksum = crypto::hash_slice(&checksum.0).to_short();
            assert_eq!(
                download.append_raw_sub_piece(&piece_checksum, checksum, Arc::new(data.clone())),
                Err(DownloaderErr::InvalidSize)
            );
        }
    }

    fn gen_random_bytes(num: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        (0..num).into_iter().map(|_| rng.gen()).collect()
    }
}
