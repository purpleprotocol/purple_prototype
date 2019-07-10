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

use crate::chain::{Chain, ChainRef};
use crate::easy_chain::block::EasyBlock;

pub type EasyChainRef<'a> = ChainRef<'a, EasyBlock>;

/// The easy chain stores blocks that represent buffered
/// validator pool join requests. If a miner wishes to become
/// a validator, it will most probably mine on the easy chain
/// (which has lower difficulty in order to populate the pool
/// more effectively).
///
/// The difficulty of the easy chain grows asymptotically with
/// the number of mined blocks since the last mined block on the
/// hard-chain so that the buffer is rate-limited.
///
/// When a block is mined on the hard chain, all of the miners
/// that have successfully mined a block on the easy chain (along
/// with the miner that successfully mined a hard block) since
/// the last mined block on the hard one are joined to the pool
/// in one operation.
///
/// Miner rewards on the easy chain are substantially less than the
/// ones on the hard chain, however, miners from the easy chain receive
/// transaction fees as additional reward because they participate in the
/// validator pool.
pub type EasyChain<'a> = Chain<'a, EasyBlock>;
