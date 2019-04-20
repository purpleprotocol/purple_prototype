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

#[derive(Clone, Debug, PartialEq)]
pub enum ValidationStatus {
    /// The orphan does not fit in any of the other categories.
    Unknown,

    /// The orphan has both a valid parent and/or children
    /// but it belongs to a chain that is disconnected from
    /// the caonical one.
    BelongsToDisconnected,

    /// The orphan belongs to a valid chain that is not canonical
    BelongsToValidChain,

    /// The orphan is the tip of a valid chain that is descended
    /// from the canonical chain.
    ValidChainTip,

    /// The orphan is the tip of a disconnected chain
    DisconnectedTip,
}