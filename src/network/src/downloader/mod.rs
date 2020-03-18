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
use crate::downloader::download_info::DownloadInfo;
use chain::Block;
use crypto::ShortHash;
use chain::TransactionBlock;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::Arc;

mod download_state;
mod download;
mod piece;
mod sub_piece;
mod sub_piece_info;
mod sub_pieces;
mod download_info;
pub mod piece_info;
pub mod error;

pub use self::piece_info::*;
pub use self::error::*;

/// Maximum allowed concurrent downloads
pub const MAX_CONCURRENT_DOWNLOADS: usize = 50;

#[derive(Clone, Debug)]
pub struct Downloader {
    /// Downloader info
    info: Arc<Mutex<DownloaderInfo>>,

    /// HashMap with all current block downloads
    block_downloads: Arc<DashMap<ShortHash, Arc<Mutex<Download>>>>, 
}

impl Downloader {
    pub fn new() -> Self {
        Downloader { 
            info: Arc::new(Mutex::new(DownloaderInfo::new())),
            block_downloads: Arc::new(DashMap::with_capacity(MAX_CONCURRENT_DOWNLOADS))
        }
    }

    /// Schedules a new block download. Returns `Err(_)` if the download cannot
    /// be scheduled.
    pub async fn from_block(&self, block: Arc<TransactionBlock>) -> Result<(), DownloaderErr> {        
        if self.block_downloads.len() >= MAX_CONCURRENT_DOWNLOADS {
            return Err(DownloaderErr::Full);
        }

        // First try to schedule the block download
        let info = self.try_schedule_block_download(block.clone()).await?;
        
        // If scheduling succeeds, write info entry
        self.write_download_info(info).await;

        Ok(())
    }

    async fn try_schedule_block_download(&self, block: Arc<TransactionBlock>) -> Result<DownloadInfo, DownloaderErr> {
        let block_hash = block.block_hash().unwrap().to_short();
        let has_block = self.block_downloads.get(&block_hash).is_some();

        if has_block {
            return Err(DownloaderErr::AlreadyHaveDownload);
        }
        
        unimplemented!();
    } 

    async fn write_download_info(&self, info: DownloadInfo) {
        unimplemented!();
    }
}

#[derive(Clone, Debug)]
pub struct DownloaderInfo {
    block_infos: Vec<DownloadInfo>,
}

impl DownloaderInfo {
    pub fn new() -> Self {
        DownloaderInfo {
            block_infos: Vec::with_capacity(MAX_CONCURRENT_DOWNLOADS),
        }
    }
}