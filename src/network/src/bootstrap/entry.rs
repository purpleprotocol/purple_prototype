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

use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug)]
pub struct BootstrapCacheEntry {
    /// The associated ip address of the bootstrap cache entry.
    pub(crate) addr: IpAddr,
}

impl BootstrapCacheEntry {
    /// Maps the ip stored in the cache entry to a `SocketAddr`
    /// with the default application port.
    pub fn to_socket_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.addr, port)
    }
}