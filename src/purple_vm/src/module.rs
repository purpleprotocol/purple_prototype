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

use crypto::Hash;
use code::function::Function;
use code::import::Import;

#[derive(Clone, Debug)]
pub struct Module {
    pub module_hash: Hash,
    pub functions: Vec<Function>,
    pub imports: Vec<Import>
}

impl PartialEq for Module {
    fn eq(&self, other: &Module) -> bool {
        &self.module_hash == &other.module_hash
    }
}