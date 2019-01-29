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

use account::{Address, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, Signature, SecretKey as Sk};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ChangeMinter {
    /// The current minter
    pub minter: Address,

    /// The address of the new minter
    pub new_minter: Address,

    /// The global identifier of the mintable asset
    pub asset_hash: Hash,

    /// The global identifier of the asset in which
    /// the transaction fee is paid in.
    pub fee_hash: Hash,

    /// The transaction's fee
    pub fee: Balance,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl ChangeMinter {
    pub const TX_TYPE: u8 = 13;
}