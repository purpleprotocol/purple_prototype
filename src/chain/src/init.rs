/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

use crate::pow_chain::chain::*;
use crate::pow_chain::PowChainState;
use lazy_static::*;
use parking_lot::RwLock;
use persistence::PersistentDb;
use std::sync::Arc;

#[cfg(feature = "test")]
use std::cell::RefCell;

#[cfg(not(feature = "test"))]
lazy_static! {
    static ref CHAIN_REF: Arc<RwLock<Option<PowChainRef>>> =
        Arc::new(RwLock::new(None));
}

#[cfg(feature = "test")]
thread_local! {
    static CHAIN_REF: RefCell<Option<PowChainRef>> = RefCell::new(None);
}

#[cfg(not(feature = "test"))]
/// Init chain module. Call this before any other function.
pub fn init(
    pow_chain_db: PersistentDb,
    archival_mode: bool,
) -> PowChainRef {
    let pow_chain = Arc::new(RwLock::new(PowChain::new(
        pow_chain_db,
        PowChainState::genesis(),
        archival_mode,
    )));
    let state_chain = Arc::new(RwLock::new(StateChain::new(
        state_chain_db,
        ChainState::new(state_db),
        archival_mode,
    )));

    let pow_chain = PowChainRef::new(pow_chain);
    let state_chain = StateChainRef::new(state_chain);

    let mut chain_ref = CHAIN_REF.write();
    *chain_ref = Some((easy_chain.clone(), pow_chain.clone(), state_chain.clone()));

    (pow_chain, state_chain)
}

#[cfg(feature = "test")]
pub fn init(
    pow_chain_db: PersistentDb,
    archival_mode: bool,
) -> PowChainRef {
    let pow_chain = Arc::new(RwLock::new(PowChain::new(
        pow_chain_db,
        PowChainState::genesis(),
        archival_mode,
    )));

    let pow_chain = PowChainRef::new(pow_chain);

    CHAIN_REF.with(|chain_ref| {
        let mut chain_ref = chain_ref.borrow_mut();
        *chain_ref = Some(pow_chain.clone());
    });

    pow_chain
}

#[cfg(not(feature = "test"))]
pub fn chain_ref() -> PowChainRef {
    let chain_ref = CHAIN_REF.read();
    chain_ref.clone().unwrap()
}

#[cfg(feature = "test")]
pub fn chain_ref() -> PowChainRef {
    CHAIN_REF.with(|chain_ref| {
        let chain_ref = chain_ref.borrow();
        chain_ref.clone().unwrap()
    })
}

#[cfg(not(feature = "test"))]
pub fn pow_chain_ref() -> PowChainRef {
    let chain_ref = CHAIN_REF.read();
    let (pow_ref, _) = chain_ref.clone().unwrap();

    pow_ref
}

#[cfg(feature = "test")]
pub fn pow_chain_ref() -> PowChainRef {
    CHAIN_REF.with(|chain_ref| {
        let chain_ref = chain_ref.borrow();
        let pow_ref = chain_ref.clone().unwrap();

        pow_ref
    })
}
