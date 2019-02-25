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
extern crate lazy_static;

extern crate byteorder;
extern crate crypto;
extern crate hashbrown;
extern crate rand;
extern crate regex;
extern crate rlp;
extern crate rust_decimal;

pub mod addresses;
pub mod balance;
pub mod multi_sig;
pub mod share_map;
pub mod shares;
pub mod signature;

pub use addresses::contract::*;
pub use addresses::multi_sig::*;
pub use addresses::normal::*;
pub use addresses::shareholders::*;
pub use addresses::*;
pub use balance::*;
pub use multi_sig::*;
pub use share_map::*;
pub use shares::*;
pub use signature::*;
