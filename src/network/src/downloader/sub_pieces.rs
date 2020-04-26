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
use crate::downloader::sub_piece_info::{SubPieceInfo, SubPieceState};
use crypto::ShortHash;
use hashbrown::HashMap;
use triomphe::Arc;

/// A set of sub-pieces
#[derive(Debug, PartialEq)]
pub struct SubPieces {
    /// Sub-pieces list
    pub(crate) sub_pieces: Vec<SubPiece>,

    /// Mapping between a sub-piece hash and its index
    pub(crate) index_mappings: HashMap<ShortHash, usize>,
}

impl SubPieces {
    pub fn new(sub_pieces: Vec<SubPiece>) -> Self {
        let mut index_mappings: HashMap<ShortHash, usize> =
            HashMap::with_capacity(sub_pieces.len());

        for (i, sub_piece) in sub_pieces.iter().enumerate() {
            index_mappings.insert(sub_piece.checksum, i);
        }

        SubPieces {
            sub_pieces,
            index_mappings,
        }
    }

    pub fn add_data(&mut self, hash: &ShortHash, data: Arc<Vec<u8>>) -> Result<(), DownloaderErr> {
        let i = self
            .index_mappings
            .get(hash)
            .ok_or(DownloaderErr::NotFound)?;
        let sub_piece = &mut self.sub_pieces[*i];
        sub_piece.add_data(data)?;

        Ok(())
    }

    pub fn is_done(&self, hash: &ShortHash) -> Result<bool, DownloaderErr> {
        let i = self
            .index_mappings
            .get(hash)
            .ok_or(DownloaderErr::NotFound)?;
        let sub_piece = &self.sub_pieces[*i];
        Ok(sub_piece.is_done())
    }

    pub fn to_info(&self, hash: &ShortHash) -> Result<SubPieceInfo, DownloaderErr> {
        let i = self
            .index_mappings
            .get(hash)
            .ok_or(DownloaderErr::NotFound)?;
        let sub_piece = &self.sub_pieces[*i];
        Ok(sub_piece.to_info())
    }

    /// Maps sub-pieces to a vector of `SubPieceInfo`
    pub fn get_infos(&self) -> Vec<SubPieceInfo> {
        self.sub_pieces.iter().map(|s| s.to_info()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds_data() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data));
        }

        let sub_pieces_struct: Vec<SubPiece> = sub_pieces.iter().map(|(s, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        for (s, data) in sub_pieces.iter() {
            assert_eq!(
                sub_pieces_struct.add_data(&s.checksum, data.clone()),
                Ok(())
            );
            assert_eq!(
                sub_pieces_struct.add_data(&s.checksum, data.clone()),
                Err(DownloaderErr::AlreadyHaveData)
            );
        }
    }

    #[test]
    fn it_fails_adding_data_bad_checksum() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data));
        }

        let sub_pieces_struct: Vec<SubPiece> = sub_pieces.iter().map(|(s, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        for (s, _) in sub_pieces.iter() {
            let random_data = b"data-r".to_vec();
            assert_eq!(
                sub_pieces_struct.add_data(&s.checksum, Arc::new(random_data)),
                Err(DownloaderErr::InvalidChecksum)
            );
        }
    }

    #[test]
    fn it_fails_adding_data_invalid_size() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data));
        }

        let sub_pieces_struct: Vec<SubPiece> = sub_pieces.iter().map(|(s, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        for (s, _) in sub_pieces.iter() {
            let random_data = b"random_data".to_vec();
            assert_eq!(
                sub_pieces_struct.add_data(&s.checksum, Arc::new(random_data)),
                Err(DownloaderErr::InvalidSize)
            );
        }
    }

    #[test]
    fn it_fails_adding_data_not_found() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data));
        }

        let sub_pieces_struct: Vec<SubPiece> = sub_pieces.iter().map(|(s, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        for (_, data) in sub_pieces.iter() {
            let checksum = crypto::hash_slice(b"random_checksum").to_short();
            assert_eq!(
                sub_pieces_struct.add_data(&checksum, data.clone()),
                Err(DownloaderErr::NotFound)
            );
        }
    }

    #[test]
    fn to_info() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let info = SubPieceInfo::new(data.len() as u64, checksum, SubPieceState::Downloaded);
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data, info));
        }

        let sub_pieces_struct: Vec<SubPiece> =
            sub_pieces.iter().map(|(s, _, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        for (s, data, info) in sub_pieces.iter() {
            sub_pieces_struct
                .add_data(&s.checksum, data.clone())
                .unwrap();
            assert_eq!(&sub_pieces_struct.to_info(&s.checksum).unwrap(), info);
        }
    }

    #[test]
    fn to_info_fails_not_found() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data));
        }

        let sub_pieces_struct: Vec<SubPiece> = sub_pieces.iter().map(|(s, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        let checksum = crypto::hash_slice(b"random_checksum").to_short();
        assert_eq!(
            sub_pieces_struct.to_info(&checksum),
            Err(DownloaderErr::NotFound)
        );
    }

    #[test]
    fn is_done() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data));
        }

        let sub_pieces_struct: Vec<SubPiece> = sub_pieces.iter().map(|(s, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        for (s, data) in sub_pieces.iter() {
            sub_pieces_struct
                .add_data(&s.checksum, data.clone())
                .unwrap();
            assert!(sub_pieces_struct.is_done(&s.checksum).unwrap());
        }
    }

    #[test]
    fn is_done_fails_not_found() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data));
        }

        let sub_pieces_struct: Vec<SubPiece> = sub_pieces.iter().map(|(s, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        let checksum = crypto::hash_slice(b"random_checksum").to_short();
        assert_eq!(
            sub_pieces_struct.is_done(&checksum),
            Err(DownloaderErr::NotFound)
        );
    }

    #[test]
    fn get_infos() {
        let mut sub_pieces = Vec::new();

        for i in 0..10 {
            let data = format!("data-{}", i).as_bytes().to_vec();
            let checksum = crypto::hash_slice(&data).to_short();
            let info = SubPieceInfo::new(data.len() as u64, checksum, SubPieceState::Downloaded);
            let mut sub_piece = SubPiece::new(data.len() as u64, checksum);
            let data = Arc::new(data);
            sub_pieces.push((sub_piece, data, info));
        }

        let sub_pieces_struct: Vec<SubPiece> =
            sub_pieces.iter().map(|(s, _, _)| s.clone()).collect();
        let mut sub_pieces_struct = SubPieces::new(sub_pieces_struct);

        for (s, data, _) in sub_pieces.iter() {
            sub_pieces_struct
                .add_data(&s.checksum, data.clone())
                .unwrap();
        }

        let infos = sub_pieces_struct.get_infos();
        for (i, (s, data, info)) in sub_pieces.iter().enumerate() {
            assert_eq!(&infos[i], info);
        }
    }
}
