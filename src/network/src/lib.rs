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

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate log;

extern crate chain;
extern crate byteorder;
extern crate crypto;
extern crate env_logger;
extern crate futures;
extern crate hashbrown;
extern crate hashdb;
extern crate hex;
extern crate parking_lot;
extern crate persistence;
extern crate rand;
extern crate rlp;
extern crate tokio;
extern crate tokio_io_timeout;
extern crate tokio_timer;
extern crate chrono;

#[cfg(test)]
pub mod mock;

mod bootstrap;
mod connection;
mod error;
mod interface;
mod network;
mod node_id;
pub mod packets;
mod peer;
mod packet;
mod common;

pub use packet::*;
pub use bootstrap::*;
pub use connection::*;
pub use error::*;
pub use interface::*;
pub use network::*;
pub use node_id::*;
pub use peer::*;

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
