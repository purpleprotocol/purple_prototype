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

use return_address::ReturnAddress;
use stack::Stack;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Frame<T: Clone> {
    locals: Stack<T>,
    return_address: ReturnAddress
}

impl<T: fmt::Debug + Clone> Frame<T> {
    pub fn new(return_address: ReturnAddress) -> Frame<T> {
        Frame {
            locals: Stack::new(),
            return_address: return_address
        }
    }
}