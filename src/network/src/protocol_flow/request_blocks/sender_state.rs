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

use std::default::Default;
use crate::protocol_flow::request_blocks::sender::RequestBlocksSenderArgs;

#[derive(Debug, Clone, PartialEq)]
pub enum RequestBlocksSenderState {
    /// The `Sender` is in stand-by, ready to send a `RequestBlocks` packet.
    Ready,

    /// The `Sender` has sent a `RequestBlocks` and is awaiting a `SendBlocks` with
    /// the specified nonce and the number of requested blocks followed by the
    /// Hash of the block from which the query starts
    Waiting(u64, RequestBlocksSenderArgs),
}

impl Default for RequestBlocksSenderState {
    fn default() -> Self {
        RequestBlocksSenderState::Ready
    }
}
