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

use crate::easy_chain::block::EasyBlock;
use std::fmt::Debug;

pub(crate) trait MergedTrait<'a>: Iterator<Item = &'a EasyBlock> + Debug {}

impl<'a, T> MergedTrait<'a> for T where T: Iterator<Item = &'a EasyBlock> + Debug {}

#[derive(Debug)]
pub struct EasyBlockIterator<'a>(pub(crate) Box<'a + MergedTrait<'a>>);

impl<'a> Iterator for EasyBlockIterator<'a> {
    type Item = &'a EasyBlock;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
