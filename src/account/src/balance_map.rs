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

use Balance;
use std::collections::HashMap;
use crypto::Hash;

#[derive(Clone, Debug)]
pub struct BalanceMap(HashMap<Hash, Balance>);

impl BalanceMap {
    pub fn new() -> BalanceMap {
        BalanceMap(HashMap::new())
    }

    /// Adds an amount of currency to the balance map.
    ///
    /// This function will panic if the given amount is negative.
    pub fn add(currency_hash: Hash, amount: Balance) {
        unimplemented!();
    }

    pub fn subtract(currency_hash: Hash, amount: Balance) {
        unimplemented!();
    }
}