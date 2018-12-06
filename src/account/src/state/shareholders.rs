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
use ShareMap;

#[derive(Clone, Debug)]
pub struct ShareholdersState {
    pub balance_map: BalanceMap,
    share_map: ShareMap,
    nonce: u64
}

impl ShareholdersState {
    pub const ACCOUNT_TYPE: u8 = 4;

    pub fn new() -> ShareholdersState {
        ShareholdersState {
            balance_map: BalanceMap::new(),
            share_map: ShareMap::new(),
            nonce: 0
        }
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ShareholdersState, &'static str> {
        unimplemented!();
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }
}