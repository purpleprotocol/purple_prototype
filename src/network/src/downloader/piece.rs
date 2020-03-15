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
use crate::downloader::sub_piece_info::SubPieceInfo;
use crate::downloader::sub_pieces::SubPieces;
use crypto::{ShortHash, BlakeHasher};
use chain::{MAX_TX_SET_SIZE, MAX_PIECE_SIZE, MAX_SUB_PIECE_SIZE};
use std::hash::Hasher;

#[derive(Debug)]
pub struct Piece {
    /// The size of the piece in bytes
    pub(crate) size: usize,

    /// Number of bytes downloaded
    pub(crate) downloaded: u64,

    /// The blake3 checksum of the piece
    pub(crate) checksum: ShortHash,

    /// Sub-pieces of the piece. This is `None` if we don't have info
    /// about the piece.
    pub(crate) sub_pieces: Option<SubPieces>

}

impl Piece {
    pub fn new(size: usize, checksum: ShortHash) -> Piece {
        Piece {
            size,
            checksum,
            downloaded: 0,
            sub_pieces: None,
        }
    }

    /// Validates provided data and if successful, returns a `Piece` with the data.
    pub fn from_data(data: &[u8], checksum: ShortHash) -> Result<Piece, DownloaderErr> {
        unimplemented!();
    }

    /// Returns a `Piece` with the provided data, performing no validation.
    /// This function will panic if the size of the data is greater than allowed.
    pub fn from_data_unchecked(data: &[u8]) -> Piece {
        unimplemented!();
    }

    pub fn from_info(info: &PieceInfo, checksum: ShortHash) -> Result<Piece, DownloaderErr> {
        let mut piece = Piece::new(info.size, checksum);
        piece.add_info(info)?;
        Ok(piece)
    }

    /// Returns `true` if we have info about this piece's sub-pieces.
    pub fn has_info(&self) -> bool {
        self.sub_pieces.is_some()
    }

    /// Adds info to the piece, verifying the checksum of the 
    /// given sub-pieces. Returns `Err(DownloaderErr::AlreadyHaveInfo)` 
    /// if we already have info or if the checksum validation failed.
    pub fn add_info(&mut self, info: &PieceInfo) -> Result<(), DownloaderErr> {
        if self.has_info() {
            return Err(DownloaderErr::AlreadyHaveInfo);
        }

        if info.sub_pieces.len() == 0 || info.sub_pieces.len() > MAX_PIECE_SIZE / MAX_SUB_PIECE_SIZE {
            return Err(DownloaderErr::InvalidInfo);
        }

        if !self.validate_checksum(info) {
            return Err(DownloaderErr::InvalidChecksum);
        }

        let mut size = 0;

        // Validate size
        for info in info.sub_pieces.iter() {
            size += info.size;
        }

        if size != self.size {
            return Err(DownloaderErr::InvalidSize);
        }

        let mut sub_pieces: Vec<SubPiece> = Vec::with_capacity(info.sub_pieces.len());

        // Create sub-pieces
        for info in info.sub_pieces.iter() {
            sub_pieces.push(SubPiece::from(info));
        }

        self.sub_pieces = Some(SubPieces::new(sub_pieces));
        Ok(())
    }

    /// Retrieves the `PieceInfo` of this `Piece`. Returns `None` if
    /// this `Piece` does not have info.  
    pub fn to_info(&self) -> Option<PieceInfo> {
        if !self.has_info() || self.sub_pieces.is_none() {
            return None;
        }

        let infos = self.sub_pieces
            .as_ref()
            .unwrap()
            .sub_pieces
            .iter()
            .map(|s| s.to_info())
            .collect();

        Some(PieceInfo::new(infos))
    }

    fn validate_checksum(&self, info: &PieceInfo) -> bool {
        let mut hasher = BlakeHasher::new();

        for piece in info.sub_pieces.iter() {
            hasher.write(&piece.checksum.0);
        }

        let hash = hasher.finish();
        let hash = encode_le_u64!(hash);
        let mut hash_bytes = [0; crypto::SHORT_HASH_BYTES];
        hash_bytes.copy_from_slice(&hash);
        let hash = ShortHash(hash_bytes);

        hash == self.checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::sub_piece_info::SubPieceInfo;
    use rand::prelude::*;
    use std::sync::Arc;

    #[test]
    fn it_fails_adding_info_invalid_checksum() {
        let mut piece = Piece::new(123, crypto::hash_slice(b"random_hash").to_short());
        let info = PieceInfo { size: 123, sub_pieces: vec![SubPieceInfo::new(123, crypto::hash_slice(b"random_checksum").to_short())] };
        assert_eq!(piece.add_info(&info), Err(DownloaderErr::InvalidChecksum));
    }

    #[test]
    fn it_fails_adding_info_empty_info() {
        let mut piece = Piece::new(123, crypto::hash_slice(b"random_hash").to_short());
        let info = PieceInfo { size: 123, sub_pieces: vec![] };
        assert_eq!(piece.add_info(&info), Err(DownloaderErr::InvalidInfo));
    }

    #[test]
    fn it_fails_adding_info_already_set() {
        let hash = get_checksum(vec![b"data".to_vec()]);
        let mut piece = Piece::new(4, hash);
        let info = PieceInfo { size: 4, sub_pieces: vec![SubPieceInfo::new(4, crypto::hash_slice(b"data").to_short())] };
        assert_eq!(piece.add_info(&info), Ok(()));
        assert_eq!(piece.add_info(&info), Err(DownloaderErr::AlreadyHaveInfo));
    }

    #[test]
    fn it_fails_invalid_sub_piece_size() {
        let hash = get_checksum(vec![b"data".to_vec()]);
        let mut piece = Piece::new(4, hash);
        let info = PieceInfo { size: 4, sub_pieces: vec![SubPieceInfo::new(6, crypto::hash_slice(b"data").to_short())] };
        assert_eq!(piece.add_info(&info), Err(DownloaderErr::InvalidSize));
    }

    #[test]
    fn to_info_it_fails_if_we_have_no_info() {
        let piece = Piece::new(123, crypto::hash_slice(b"random_hash").to_short());
        assert_eq!(piece.to_info(), None);
    }

    #[test]
    fn it_doesnt_have_info() {
        let piece = Piece::new(123, crypto::hash_slice(b"random_hash").to_short());
        assert!(!piece.has_info());
    }

    #[test]
    fn it_adds_info() {
        let hash = get_checksum(vec![b"data".to_vec()]);
        let mut piece = Piece::new(4, hash);
        let info = PieceInfo { size: 4, sub_pieces: vec![SubPieceInfo::new(4, crypto::hash_slice(b"data").to_short())] };
        assert_eq!(piece.add_info(&info), Ok(()));
    }

    #[test]
    fn it_adds_info_stress() {
        // Run 10 times
        for _ in (0..10) {
            let mut rng = rand::thread_rng();
            let num = rng.gen_range(1, MAX_TX_SET_SIZE);
            let bytes = gen_random_bytes(num);
            let pieces = chunk(bytes);
            let infos: Vec<(PieceInfo, ShortHash)> = pieces
                .iter()
                .map(|s| (s.to_info().unwrap(), s.checksum))
                .collect();

            for (info, checksum) in infos.iter() {
                if let Err(err) = Piece::from_info(info, *checksum) {
                    panic!("Failed: {:?}", err);
                }
            }
        }
    }

    fn chunk(bytes: Vec<u8>) -> Vec<Piece> {
        if bytes.len() == 0 {
            panic!("Cannot chunk 0 bytes");
        }

        if bytes.len() > MAX_TX_SET_SIZE {
            panic!("Cannot chunk more bytes than the MAX_TX_SET_SIZE constant");
        }

        let pieces_count = if bytes.len() / MAX_PIECE_SIZE == 0 {
            1
        } else {
            bytes.len() / MAX_PIECE_SIZE
        };
        assert_ne!(pieces_count, 0);
        let mut buf = Vec::with_capacity(pieces_count);

        for i in 0..pieces_count {
            let i = i * MAX_PIECE_SIZE;
            let start_i = i;
            let end_i = if i == pieces_count - 1 {
                i + (bytes.len() % MAX_PIECE_SIZE)
            } else {
                i + MAX_PIECE_SIZE
            };

            let raw_piece = &bytes[start_i..end_i].to_vec();
            assert!(raw_piece.len() > 0);
            assert!(raw_piece.len() <= MAX_PIECE_SIZE);
            let sub_pieces = chunk_piece(&raw_piece);
            let raw_sub_pieces = sub_pieces
                .iter()
                .map(|s| s.data.as_ref().unwrap().as_ref().clone())
                .collect();
            let checksum = get_checksum(raw_sub_pieces);
            let mut piece = Piece::new(raw_piece.len(), checksum);
            piece.sub_pieces = Some(SubPieces::new(sub_pieces));
            buf.push(piece);
        }

        buf
    }

    fn chunk_piece(bytes: &[u8]) -> Vec<SubPiece> {
        if bytes.len() == 0 {
            panic!("Cannot chunk 0 bytes");
        }

        let sub_pieces_count = if bytes.len() / MAX_SUB_PIECE_SIZE == 0 {
            1
        } else {
            bytes.len() / MAX_SUB_PIECE_SIZE
        };
        assert_ne!(sub_pieces_count, 0);
        let mut buf = Vec::with_capacity(sub_pieces_count);

        for i in 0..sub_pieces_count {
            let i = i * MAX_SUB_PIECE_SIZE;
            let start_i = i;
            let end_i = if i == sub_pieces_count - 1 {
                i + (bytes.len() % MAX_SUB_PIECE_SIZE)
            } else {
                i + MAX_SUB_PIECE_SIZE
            };

            let raw_sub_piece = &bytes[start_i..end_i].to_vec();
            assert!(raw_sub_piece.len() > 0);
            assert!(raw_sub_piece.len() <= MAX_SUB_PIECE_SIZE);
            let checksum = crypto::hash_slice(raw_sub_piece).to_short();
            let mut sub_piece = SubPiece::new(raw_sub_piece.len(), checksum);
            sub_piece.add_data(Arc::new(raw_sub_piece.to_vec())).unwrap();
            buf.push(sub_piece);
        }

        buf
    }

    fn get_checksum(data: Vec<Vec<u8>>) -> ShortHash {
        let mut hasher = BlakeHasher::new();
        for data in data.iter() {
            let hash = crypto::hash_slice(&data).to_short();
            hasher.write(&hash.0);
        }
        let hash = hasher.finish();
        let hash = encode_le_u64!(hash);
        let mut hash_bytes = [0; crypto::SHORT_HASH_BYTES];
        hash_bytes.copy_from_slice(&hash);
        ShortHash(hash_bytes)
    }

    fn gen_random_bytes(num: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        
        (0..num)
            .into_iter()
            .map(|_| rng.gen())
            .collect()
    }
}