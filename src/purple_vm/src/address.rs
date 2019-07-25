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

#[derive(Debug, Clone)]
pub struct Address {
    pub ip: usize,
    pub fun_idx: usize,
    pub module_idx: usize,
}

impl Address {
    pub fn new(ip: usize, fun_idx: usize, module_idx: usize) -> Address {
        Address {
            ip: ip,
            fun_idx: fun_idx,
            module_idx: module_idx,
        }
    }

    /// Increments the instruction pointer.
    pub fn increment(&mut self) {
        self.ip += 1;
    }

    pub fn set_ip(&mut self, new_ip: usize) {
        self.ip = new_ip;
    }
}
