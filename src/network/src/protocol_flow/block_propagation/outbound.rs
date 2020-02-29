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

use crate::packets::*;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq)]
/// Wrapper over an outbound packet in this state-machine.
pub enum OutboundPacket {
    AnnounceCheckpoint(Arc<AnnounceCheckpoint>),
    AnnounceTxBlock(Arc<AnnounceTxBlock>),
    ForwardCheckpointHeader(Arc<ForwardCheckpointHeader>),
    ForwardTxBlockHeader(Arc<ForwardTxBlockHeader>),
    SendMissingTxs(Arc<SendMissingTxs>),
}
