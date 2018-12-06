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

    /// Returns the amount of the given currency stored in the balance map.
    ///
    /// Returns `None` if there is no entry for the given currency.
    pub fn get(&self, currency_hash: Hash) -> Option<Balance> {
        match self.0.get(&currency_hash) {
            Some(result) => Some(result.clone()),
            None         => None
        }
    }

    /// Adds an amount of currency to the balance map.
    pub fn add(&mut self, currency_hash: Hash, amount: Balance) {
        match self.0.clone().get(&currency_hash) {
            Some(result) => {
                self.0.insert(currency_hash, amount + result.clone());
            },
            None => {
                self.0.insert(currency_hash, amount);
            }
        }
    }

    /// Subtracts an amount from the balance map
    ///
    /// This funcion will panic if there is no entry for the given currency in the balance map.
    pub fn subtract(&mut self, currency_hash: Hash, amount: Balance) {
        match self.0.clone().get(&currency_hash) {
            Some(result) => {
                self.0.insert(currency_hash, amount - result.clone());
            },
            None => {
                panic!("There is no entry for the currency {:#?}", currency_hash);
            }
        }
    }
}