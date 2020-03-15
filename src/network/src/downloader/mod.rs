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

use crate::downloader::download::Download;
use crate::downloader::error::DownloaderErr;
use crypto::ShortHash;
use chain::TransactionBlock;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;

mod download_state;
mod download;
mod piece;
mod sub_piece;
mod sub_piece_info;
mod sub_pieces;
pub mod piece_info;
pub mod error;

pub use self::piece_info::*;
pub use self::error::*;

/// Maximum allowed concurrent downloads
pub const MAX_CONCURRENT_DOWNLOADS: usize = 1000;

#[derive(Clone, Debug)]
pub struct Downloader {
    block_downloads: Arc<RwLock<HashMap<ShortHash, Arc<Mutex<Download>>>>>, 
}

impl Downloader {
    pub fn new() -> Self {
        Downloader { 
            block_downloads: Arc::new(RwLock::new(HashMap::with_capacity(MAX_CONCURRENT_DOWNLOADS)))
        }
    }

    /// Schedules a new block download. Returns `Err(_)` if the download cannot
    /// be scheduled.
    pub fn from_block(&self, block: Arc<TransactionBlock>) -> Result<(), DownloaderErr> {
        let block_downloads = self.block_downloads.read();
        
        if block_downloads.len() >= MAX_CONCURRENT_DOWNLOADS {
            return Err(DownloaderErr::Full);
        }
        
        unimplemented!();
    }
}