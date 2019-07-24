/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

#![allow(non_snake_case)]

mod block;
mod chain;
mod easy_chain;
mod hard_chain;
mod state_chain;
mod types;
mod pow_chain_state;

pub use crate::chain::*;
pub use block::*;
pub use easy_chain::block::*;
pub use easy_chain::chain::*;
pub use hard_chain::block::*;
pub use hard_chain::chain::*;
pub use state_chain::block::*;
pub use state_chain::chain::*;
pub use state_chain::state::*;
pub use pow_chain_state::*;

#[cfg(test)]
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

#[cfg(test)]
use rand::prelude::*;

#[cfg(test)]
pub fn random_socket_addr() -> SocketAddr {
    let mut thread_rng = rand::thread_rng();
    let i1 = thread_rng.gen();
    let i2 = thread_rng.gen();
    let i3 = thread_rng.gen();
    let i4 = thread_rng.gen();

    let addr = IpAddr::V4(Ipv4Addr::new(i1, i2, i3, i4));
    SocketAddr::new(addr, 44034)
}
