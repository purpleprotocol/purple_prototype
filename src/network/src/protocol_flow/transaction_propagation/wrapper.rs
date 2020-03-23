/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::protocol_flow::transaction_propagation::*;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::default::Default;
use triomphe::Arc;

/// The pairs buffer size. This number represents
/// the maximum amount of transactions that can be
/// concurrently propagated at the same time for one
/// peer.
pub const TX_PAIRS_BUFFER_SIZE: usize = 8000;

#[derive(Clone, Debug)]
pub struct TransactionPropagation {
    /// For maximum performance, model the transaction
    /// propagation protocol flow as a mapping between
    /// nonces, representing a propagated transaction,
    /// and `Sender/Receiver` pairs. In this way, we can
    /// concurrently propagate multiple transactions.
    pub(crate) pairs: Arc<DashMap<u64, Pair>>,
}

impl Default for TransactionPropagation {
    fn default() -> Self {
        TransactionPropagation {
            pairs: Arc::new(DashMap::with_capacity(TX_PAIRS_BUFFER_SIZE)),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Pair {
    pub(crate) sender: Arc<Mutex<TxSender>>,
    pub(crate) receiver: Arc<Mutex<TxReceiver>>,
}
