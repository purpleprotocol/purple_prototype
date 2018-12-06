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

use BalanceMap;
use NormalAddress;

#[derive(Clone, Debug)]
pub struct MultiSigState {
    keys: Vec<NormalAddress>,
    required_keys: u8,
    pub balance_map: BalanceMap,
    nonce: u64  
}

impl MultiSigState {
    pub const ACCOUNT_TYPE: u8 = 3;

    pub fn new(keys: Vec<NormalAddress>, required_keys: u8) -> MultiSigState {
        MultiSigState {
            keys: keys,
            required_keys: required_keys,
            balance_map: BalanceMap::new(),
            nonce: 0
        }
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<MultiSigState, &'static str> {
        unimplemented!();
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }
}