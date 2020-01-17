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

use enum_repr::*;

#[EnumRepr(type = "usize")]
#[derive(Copy, Clone, Debug, PartialEq)]
/// All possible plugins that can be used for mining.
///
/// Each type is mapped to its index in the loaded plugins list.
pub enum PluginType {
    Cuckoo24 = 0,
    Cuckoo25 = 1,
    Cuckoo26 = 2,
    Cuckoo27 = 3,
    Cuckoo28 = 4,
    Cuckoo29 = 5,
    Cuckoo30 = 6,
    Cuckoo31 = 7,
    Cuckoo0 = 8,
}
