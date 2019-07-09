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

#[derive(Clone, Debug, PartialEq)]
pub enum VmError {
    /// The module is not loaded.
    NoModule,

    /// The function with the given index is not defined.
    NoFun,

    /// The called module is not loaded.
    NotLoaded,

    /// The called function is not defined.
    NotDefined,

    /// The module containing the function imported at
    /// (module idx, import idx) is not loaded.
    ImportNotLoaded(usize, usize),

    /// The module is already loaded.
    AlreadyLoaded,

    /// Integer overflow
    Overflow,

    /// Float overflow
    Infinity,

    /// Divide by zero
    DivideByZero
}
