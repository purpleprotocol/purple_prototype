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

use chain::PowBlock;
use std::default::Default;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum BlockSenderState {
    /// The `Sender` is ready to send an `AnnounceCheckpoint` or `AnnounceTxBlock` packet.
    Ready,

    /// The `Sender` is waiting for a `RequestBlock` or `RejectBlock` packet.
    WaitingResponse(u64, Arc<PowBlock>),

    /// The `Sender` has forwarded the header of a block and is now waiting
    /// to be requested transaction data.
    ForwardedHeader(u64, Arc<PowBlock>),

    /// The state-machine is done.
    Done,
}

impl Default for BlockSenderState {
    fn default() -> Self {
        BlockSenderState::Ready
    }
}
