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

use crate::downloader::download_info::DownloadInfo;
use crate::downloader::download_state::DownloadState;
use crate::downloader::piece::Piece;
use chrono::*;
use crypto::ShortHash;

#[derive(Debug)]
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
}

impl Download {
    pub fn from_pieces(size: u64, pieces: Vec<Piece>, priority: u64) -> Self {
        unimplemented!();
    }

    pub fn from_checksums_and_sizes(checksums: &[(ShortHash, u64)], priority: u64) -> Self {
        unimplemented!();
    }

    pub fn to_info(&self) -> DownloadInfo {
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