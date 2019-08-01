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

use crate::easy_chain::chain::*;
use crate::hard_chain::chain::*;
use crate::state_chain::chain::*;
use crate::pow_chain_state::PowChainState;
use crate::hard_chain::state::HardChainState;
use crate::state_chain::state::ChainState;
use std::sync::Arc;
use lazy_static::*;
use parking_lot::RwLock;
use persistence::PersistentDb;

#[cfg(feature = "test")]
use std::cell::RefCell;

#[cfg(not(feature = "test"))]
lazy_static! {
    static ref CHAIN_REFS: Arc<RwLock<Option<(EasyChainRef, HardChainRef, StateChainRef)>>> = Arc::new(RwLock::new(None));
}

#[cfg(feature = "test")]
thread_local! {
    static CHAIN_REFS: RefCell<Option<(EasyChainRef, HardChainRef, StateChainRef)>> = RefCell::new(None);
}

#[cfg(not(feature = "test"))]
/// Init chain module. Call this before any other function.
pub fn init(
    easy_chain_db: PersistentDb, 
    hard_chain_db: PersistentDb,
    state_chain_db: PersistentDb,
    state_db: PersistentDb,
    archival_mode: bool,
) -> (EasyChainRef, HardChainRef, StateChainRef) {
    let easy_chain = Arc::new(RwLock::new(EasyChain::new(
        easy_chain_db,
        PowChainState::genesis(),
        archival_mode,
    )));
    let easy_chain = EasyChainRef::new(easy_chain);
    let hard_chain = Arc::new(RwLock::new(HardChain::new(
        hard_chain_db,
        HardChainState::genesis_init(easy_chain.clone()),
        archival_mode,
    )));
    let state_chain = Arc::new(RwLock::new(StateChain::new(
        state_chain_db,
        ChainState::new(state_db),
        archival_mode,
    )));

    let hard_chain = HardChainRef::new(hard_chain);
    let state_chain = StateChainRef::new(state_chain);

    let mut refs = CHAIN_REFS.write();
    *refs = Some((easy_chain.clone(), hard_chain.clone(), state_chain.clone()));

    (easy_chain, hard_chain, state_chain)
}

#[cfg(feature = "test")]
pub fn init(
    easy_chain_db: PersistentDb, 
    hard_chain_db: PersistentDb,
    state_chain_db: PersistentDb,
    state_db: PersistentDb,
    archival_mode: bool,
) -> (EasyChainRef, HardChainRef, StateChainRef) {
    let easy_chain = Arc::new(RwLock::new(EasyChain::new(
        easy_chain_db,
        PowChainState::genesis(),
        archival_mode,
    )));
    let easy_chain = EasyChainRef::new(easy_chain);
    let hard_chain = Arc::new(RwLock::new(HardChain::new(
        hard_chain_db,
        HardChainState::genesis_init(easy_chain.clone()),
        archival_mode,
    )));
    let state_chain = Arc::new(RwLock::new(StateChain::new(
        state_chain_db,
        ChainState::new(state_db),
        archival_mode,
    )));

    let hard_chain = HardChainRef::new(hard_chain);
    let state_chain = StateChainRef::new(state_chain);

    CHAIN_REFS.with(|refs| {
        let mut refs = refs.borrow_mut();
        *refs = Some((easy_chain.clone(), hard_chain.clone(), state_chain.clone()));
    });

    (easy_chain, hard_chain, state_chain)
}

#[cfg(not(feature = "test"))]
pub fn chain_refs() -> (EasyChainRef, HardChainRef, StateChainRef) {
    let refs = CHAIN_REFS.read();
    refs.clone().unwrap()
}

#[cfg(feature = "test")]
pub fn chain_refs() -> (EasyChainRef, HardChainRef, StateChainRef) {
    CHAIN_REFS.with(|refs| {
        let refs = refs.borrow();
        refs.clone().unwrap()
    })
}

#[cfg(not(feature = "test"))]
pub fn easy_chain_ref() -> EasyChainRef {
    let refs = CHAIN_REFS.read();
    let (easy_ref, _, _) = refs.clone().unwrap();

    easy_ref
}

#[cfg(feature = "test")]
pub fn easy_chain_ref() -> EasyChainRef {
    CHAIN_REFS.with(|refs| {
        let refs = refs.borrow();
        let (easy_ref, _, _) = refs.clone().unwrap();

        easy_ref
    })
}

#[cfg(not(feature = "test"))]
pub fn hard_chain_ref() -> HardChainRef {
    let refs = CHAIN_REFS.read();
    let (_, hard_ref, _) = refs.clone().unwrap();

    hard_ref
}

#[cfg(feature = "test")]
pub fn hard_chain_ref() -> HardChainRef {
    CHAIN_REFS.with(|refs| {
        let refs = refs.borrow();
        let (_, hard_ref, _) = refs.clone().unwrap();

        hard_ref
    })
}

#[cfg(not(feature = "test"))]
pub fn state_chain_ref() -> StateChainRef {
    let refs = CHAIN_REFS.read();
    let (_, _, state_ref) = refs.clone().unwrap();

    state_ref
}

#[cfg(feature = "test")]
pub fn state_chain_ref() -> StateChainRef {
    CHAIN_REFS.with(|refs| {
        let refs = refs.borrow();
        let (_, _, state_ref) = refs.clone().unwrap();

        state_ref
    })
}