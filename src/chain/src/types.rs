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

use crate::chain::ChainErr;
use std::fmt::Debug;

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum OrphanType {
    /// The orphan has both a valid parent and/or children
    /// but it belongs to a chain that is disconnected from
    /// the canonical one.
    BelongsToDisconnected,

    /// The orphan belongs to a valid chain that is not canonical
    BelongsToValidChain,

    /// The orphan is the tip of a valid chain that is descended
    /// from the canonical chain.
    ValidChainTip,

    /// The orphan is the tip of a disconnected chain
    DisconnectedTip,
}

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum BranchType {
    /// The canonical chain branch
    Canonical,
    
    /// A non-canonical chain branch
    NonCanonical,
}

/// Generic trait for state that can be flushed to disk.
pub trait Flushable {
    fn flush(&mut self) -> Result<(), ChainErr>;
}

/// Chain state wrapper representing an in-memory state
/// that is not yet flushed to disk.
#[derive(Clone, PartialEq, Debug)]
pub struct UnflushedChainState<S>
where
    S: Debug + Sized + Flushable + Clone + PartialEq,
{
    state: S,
}

impl<S> UnflushedChainState<S>
where
    S: Debug + Sized + Flushable + Clone + PartialEq,
{
    pub fn new(state: S) -> UnflushedChainState<S> {
        UnflushedChainState { state }
    }

    pub fn inner(self) -> S {
        self.state
    }

    pub fn flush(mut self) -> Result<FlushedChainState<S>, ChainErr> {
        self.state.flush()?;
        Ok(FlushedChainState { state: self.state })
    }
}

/// Chain state wrapper representing state that is flushed
/// to disk. This is not modifiable and read-only. To request
/// a modifiable state which is un-flushed, call `Self::modify()`.
#[derive(Clone, PartialEq, Debug)]
pub struct FlushedChainState<S>
where
    S: Debug + Sized + Flushable + Clone + PartialEq,
{
    state: S,
}

impl<S> FlushedChainState<S>
where
    S: Debug + Sized + Flushable + Clone + PartialEq,
{
    pub fn new(state: S) -> FlushedChainState<S> {
        FlushedChainState { state }
    }

    pub fn inner(self) -> S {
        self.state
    }

    pub fn modify(self) -> UnflushedChainState<S> {
        UnflushedChainState { state: self.state }
    }
}
