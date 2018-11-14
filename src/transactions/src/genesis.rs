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

use account::{Address, Balance, Shares};
use crypto::{Hash, Signature};
use serde::{Deserialize, Serialize};
use transaction::*;

#[derive(Serialize, Deserialize)]
pub struct Genesis {
    treasury_balance: Balance,
    treasury_address: Address,
    treasury_shares: Shares,
    treasury_stock_hash: Hash,
    currency_hash: Hash,
    coin_supply: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
}
