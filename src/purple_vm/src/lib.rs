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

#![allow(non_camel_case_types)]

#[cfg(test)]
extern crate test_helpers;

#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate enum_repr;
#[macro_use]
extern crate bin_tools;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;

extern crate bitvec;
extern crate byteorder;
extern crate crypto;
extern crate hashbrown;
extern crate patricia_trie;
extern crate persistence;
extern crate rand;
extern crate regex;
extern crate rust_decimal;

pub use code::*;
pub use error::*;
pub use gas::*;
pub use virtual_machine::*;

mod address;
mod code;
mod error;
mod frame;
mod gas;
mod instruction_set;
mod module;
mod primitives;
mod stack;
mod virtual_machine;
