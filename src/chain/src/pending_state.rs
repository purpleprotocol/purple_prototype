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

use crypto::Hash;
use hashbrown::{HashMap, HashSet};

#[derive(Clone, Debug)]
/// Mapping between the heads of chains following
/// a certain parent hash.
pub struct Branches(pub(crate) HashMap<Hash, PendingState>);

impl Branches {
    pub fn new() -> Branches {
        Branches(HashMap::new())
    }

    /// Inserts a new branch
    pub fn insert(&mut self, head: Hash, tips: &[(Hash, u64)], largest_height: Option<u64>) {
        self.0.insert(head, PendingState::new(tips, largest_height));
    }

    pub fn insert_branch_end(&mut self, head: &Hash, end: Hash, height: u64) -> Result<(), ()> {
        if let Some(state) = self.0.get_mut(head) {
            state.add_end(end, height);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a Hash, &'a PendingState)> {
        self.0.iter()
    }

    pub fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = (&'a Hash, &'a mut PendingState)> {
        self.0.iter_mut()
    }
}

#[derive(Clone, Debug)]
/// State of a pending chain
pub struct PendingState {
    /// The tips of the branch and their heights.
    pub(crate) tips: HashMap<Hash, u64>,

    /// The largest height of the pending tips.
    pub(crate) largest_height: Option<u64>,

}

impl PendingState {
    pub fn new(tips: &[(Hash, u64)], largest_height: Option<u64>) -> PendingState {
        PendingState {
            tips: tips.iter().cloned().collect(),
            largest_height
        }
    }

    pub fn remove_tip(&mut self, tip: &Hash) {
        if let Some(_) = self.tips.remove(tip){
            if !self.tips.is_empty() {
                let mut buf: Vec<(&Hash, &u64)> = self.tips.iter().collect();

                buf.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));
                let (_, highest) = buf.pop().unwrap();

                self.largest_height = Some(*highest)
            } else {
                self.largest_height = None;
            }
        }
    }

    pub fn add_end(&mut self, end: Hash, height: u64) {
        self.tips.insert(end, height);

        if let Some(h) = self.largest_height {
            if height > h {
                self.largest_height = Some(height);
            }
        } else {
            self.largest_height = Some(height);
        }
    }
}