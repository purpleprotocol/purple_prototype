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

#![allow(non_snake_case, unused, deprecated)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate bin_tools;

mod block;
mod chain;
mod init;
mod pow_chain;
pub mod types;

#[cfg(any(test, feature = "test"))]
mod test_helpers;

pub use crate::block::*;
pub use crate::chain::*;
pub use crate::init::*;
pub use crate::pow_chain::block::*;
pub use crate::pow_chain::chain::*;
pub use crate::pow_chain::*;

#[cfg(any(test, feature = "test"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(any(test, feature = "test"))]
use rand::prelude::*;

#[cfg(any(test, feature = "test"))]
pub fn random_socket_addr() -> SocketAddr {
    let mut thread_rng = rand::thread_rng();
    let i1 = thread_rng.gen();
    let i2 = thread_rng.gen();
    let i3 = thread_rng.gen();
    let i4 = thread_rng.gen();

    let addr = IpAddr::V4(Ipv4Addr::new(i1, i2, i3, i4));
    SocketAddr::new(addr, 44034)
}

static_assertions::const_assert_eq!(crate::MAX_TX_SET_SIZE % crate::MAX_PIECE_SIZE, 0);
static_assertions::const_assert_eq!(crate::MAX_PIECE_SIZE % crate::MAX_SUB_PIECE_SIZE, 0);