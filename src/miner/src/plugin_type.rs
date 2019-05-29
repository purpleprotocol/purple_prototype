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

use enum_repr::*;

#[EnumRepr(type = "usize")]
#[derive(Copy, Clone, Debug, PartialEq)]
/// All possible plugins that can be used for mining.
/// 
/// Each type is mapped to its index in the loaded plugins list.
pub enum PluginType {
    Cuckoo19 = 0,
    Cuckoo24 = 1,
    Cuckoo25 = 2,
    Cuckoo26 = 3,
    Cuckoo27 = 4,
    Cuckoo28 = 5,
    Cuckoo29 = 6,
    Cuckoo30 = 7,
    Cuckoo31 = 8,
}