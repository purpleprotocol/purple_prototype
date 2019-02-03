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

use value::VmValue;

#[derive(Clone, Debug)]
pub struct Function {
    /// The number of arguments that the function receives.
    pub arity: u8,

    /// The block of code associated with the function.
    pub block: Vec<u8>,

    /// The name of the function.
    pub name: String,
    
    /// The types of the arguments.
    pub arguments: Vec<VmValue>,

    // The return type of the function.
    pub return_type: VmValue
}