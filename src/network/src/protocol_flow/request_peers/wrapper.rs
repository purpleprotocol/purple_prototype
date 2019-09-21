/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

use crate::protocol_flow::request_peers::*;
use crate::bootstrap::cache::BootstrapCache;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct RequestPeers {
    pub(crate) sender: Arc<Mutex<RequestPeersSender>>,
    pub(crate) receiver: Arc<Mutex<RequestPeersReceiver>>,
}

impl RequestPeers {
    pub fn new(bootstrap_cache: BootstrapCache) -> RequestPeers {
        RequestPeers {
            sender: Default::default(),
            receiver: Arc::new(Mutex::new(RequestPeersReceiver::new(bootstrap_cache))),
        }
    }
}
