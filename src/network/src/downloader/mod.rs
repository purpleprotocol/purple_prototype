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
use triomphe::Arc;
use constants::*;

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

/// Maximum amount of active downloads
pub const MAX_ACTIVE_DOWNLOAD: usize = 5;

#[derive(Clone, Debug)]
pub struct Downloader {
    /// Downloader info
    info: DownloaderInfo,

    /// HashMap with all current block downloads
    block_downloads: Arc<DashMap<ShortHash, Arc<Mutex<Download>>>>, 
}

impl Downloader {
    pub fn new() -> Self {
        Downloader { 
            info: DownloaderInfo::new(),
            block_downloads: Arc::new(DashMap::with_capacity(MAX_CONCURRENT_DOWNLOADS))
        }
    }

    /// Schedules a new block download. Returns `Err(_)` if the download cannot
    /// be scheduled.
    pub async fn from_block(&self, block: Arc<TransactionBlock>, priority: u64) -> Result<(), DownloaderErr> {        
        debug!("Scheduling block download for hash: {}, height: {}", block.block_hash().unwrap(), block.height());
        
        if self.block_downloads.len() >= MAX_CONCURRENT_DOWNLOADS {
            let err = DownloaderErr::Full;
            debug!("Scheduling failed for hash: {}, height: {}, reason: {:?}", block.block_hash().unwrap(), block.height(), err);
            return Err(err);
        }

        // First try to schedule the block download
        let info = self.try_schedule_block_download(block.clone(), priority).await?;
        
        // If scheduling succeeds, write info entry
        self.write_download_info(block.clone(), info).await;

        debug!("Scheduling succeeded for hash: {}, height: {}", block.block_hash().unwrap(), block.height());

        Ok(())
    }

    /// Returns the current downloader info
    pub fn get_info(&self) -> DownloaderInfo {
        self.info.clone()
    }

    pub fn query_block(&self, hash: &ShortHash) -> Option<Arc<Mutex<Download>>> {
        self.block_downloads.get(hash).map(|r| r.clone())
    }

    pub fn remove_block(&self, hash: &ShortHash) -> Option<Arc<Mutex<Download>>> {
        self.block_downloads.remove(hash).map(|(_, r)| r)
    }

    async fn try_schedule_block_download(&self, block: Arc<TransactionBlock>, priority: u64) -> Result<DownloadInfo, DownloaderErr> {
        let block_hash = block.block_hash().unwrap().to_short();
        let has_block = self.block_downloads.get(&block_hash).is_some();

        if has_block {
            let err = DownloaderErr::AlreadyHaveDownload;
            debug!("Scheduling failed for hash: {}, height: {}, reason: {:?}", block.block_hash().unwrap(), block.height(), err);
            return Err(err);
        }

        let tx_checksums = block.tx_checksums.as_ref().unwrap();
        let pieces_sizes = block.pieces_sizes.as_ref().unwrap();

        if tx_checksums.len() == 0 || tx_checksums.len() != pieces_sizes.len() || tx_checksums.len() > MAX_TX_SET_SIZE / MAX_PIECE_SIZE {
            return Err(DownloaderErr::InvalidBlockHeader);
        }

        let checksums: Vec<(ShortHash, u64)> = tx_checksums
            .iter()
            .enumerate()
            .map(|(i, checksum)| {
                let size = pieces_sizes[i];
                (checksum.clone(), size as u64)
            })
            .collect();

        // Schedule block download
        let download = Download::from_checksums_and_sizes(&checksums, 0)?;
        let info = download.to_info();
        let download = Arc::new(Mutex::new(download));
        let block_hash = block.block_hash().unwrap();
        self.block_downloads.insert(block_hash.to_short(), download);

        Ok(info)
    } 

    async fn write_download_info(&self, block: Arc<TransactionBlock>, info: DownloadInfo) {
        let block_hash = block.block_hash().unwrap().to_short();
        self.info.block_infos.insert(block_hash, info);
    }
}

#[derive(Clone, Debug)]
pub struct DownloaderInfo {
    pub(crate) block_infos: Arc<DashMap<ShortHash, DownloadInfo>>,
}

impl DownloaderInfo {
    pub fn new() -> Self {
        DownloaderInfo {
            block_infos: Arc::new(DashMap::with_capacity(MAX_CONCURRENT_DOWNLOADS)),
        }
    }
}