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

#![feature(test)]

#[cfg(test)]
extern crate test;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[macro_use]
extern crate serde_derive;

extern crate merkle_light;
extern crate parking_lot;
extern crate rayon;
extern crate account;
extern crate byteorder;
extern crate causality;
extern crate crypto;
extern crate network;
extern crate rlp;
extern crate serde;
extern crate transactions;
extern crate patricia_trie;
extern crate persistence;

#[macro_use]
mod macros;
mod heartbeat;
mod join;
mod leave;

pub use heartbeat::*;
pub use join::*;
pub use leave::*;