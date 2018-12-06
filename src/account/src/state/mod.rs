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

pub mod normal;
pub mod multi_sig;
pub mod shareholders;
pub mod contract;

pub use state::contract::*;
pub use state::normal::*;
pub use state::multi_sig::*;
pub use state::shareholders::*;

use BalanceMap;

#[derive(Clone, Debug)]
pub enum AccountState {
    Normal(NormalState),
    Contract(ContractState),
    MultiSig(MultiSigState),
    Shareholders(ShareholdersState)
}

impl AccountState {
    pub fn increment_nonce(&mut self) {
        match *self {
            AccountState::Normal(ref mut acc)       => acc.increment_nonce(),
            AccountState::Contract(ref mut acc)     => acc.increment_nonce(),
            AccountState::MultiSig(ref mut acc)     => acc.increment_nonce(),
            AccountState::Shareholders(ref mut acc) => acc.increment_nonce()
        }  
    }

    pub fn balance_map(&mut self) -> &mut BalanceMap {
        match *self {
            AccountState::Normal(ref mut acc)       => &mut acc.balance_map,
            AccountState::Contract(ref mut acc)     => &mut acc.balance_map,
            AccountState::MultiSig(ref mut acc)     => &mut acc.balance_map,
            AccountState::Shareholders(ref mut acc) => &mut acc.balance_map
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<AccountState, &'static str> {
        let first_byte = bytes[0];

        match first_byte {
            1 => match NormalState::from_bytes(bytes) {
                Ok(result) => Ok(AccountState::Normal(result)),
                Err(err)   => Err(err)
            },
            2 => match ContractState::from_bytes(bytes) {
                Ok(result) => Ok(AccountState::Contract(result)),
                Err(err)   => Err(err)
            },
            3 => match MultiSigState::from_bytes(bytes) {
                Ok(result) => Ok(AccountState::MultiSig(result)),
                Err(err)   => Err(err)
            },
            4 => match ShareholdersState::from_bytes(bytes) {
                Ok(result) => Ok(AccountState::Shareholders(result)),
                Err(err)   => Err(err)
            },
            _ => Err("Invalid first byte!")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            AccountState::Normal(ref acc)       => acc.to_bytes(),
            AccountState::Contract(ref acc)     => acc.to_bytes(),
            AccountState::MultiSig(ref acc)     => acc.to_bytes(),
            AccountState::Shareholders(ref acc) => acc.to_bytes()
        }
    }
}
