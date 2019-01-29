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

pub const ASSET_NAME_SIZE: usize = 32;
pub const META_FIELD_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateUnique {
    /// The asset creator's address
    pub creator: Address,

    /// The receiver of the asset
    pub receiver: Address,

    /// The global identifier of the asset
    pub asset_hash: Hash,

    /// The id of the currency that the transaction is paid in
    pub fee_hash: Hash,

    /// The name of the asset
    pub name: [u8; ASSET_NAME_SIZE],

    // 5 optional fields of 32 bytes for metadata. 160 bytes in total.
    pub meta1: Option<[u8; META_FIELD_SIZE]>,
    pub meta2: Option<[u8; META_FIELD_SIZE]>,
    pub meta3: Option<[u8; META_FIELD_SIZE]>,
    pub meta4: Option<[u8; META_FIELD_SIZE]>,
    pub meta5: Option<[u8; META_FIELD_SIZE]>,

    /// The fee of the transaction
    pub fee: Balance,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl CreateUnique {
    pub const TX_TYPE: u8 = 12;
}
