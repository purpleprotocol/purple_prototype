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

use crate::error::BloomErr;
use bloomfilter::Bloom as BloomFilter;

/// The size of an item in the bloom filter in bytes
pub const ITEM_SIZE: usize = 32;

pub struct Bloom {
    inner: BloomFilter<[u8; ITEM_SIZE]>,
}

impl Bloom {
    pub fn new(bitmap_size: usize, items_count: usize) -> Bloom {
        Bloom {
            inner: BloomFilter::new(bitmap_size, items_count)
        }
    }

    pub fn set(&mut self, item: &[u8; ITEM_SIZE]) {
        self.inner.set(item);
    }

    pub fn check(&self, item: &[u8; ITEM_SIZE]) -> bool {
        self.inner.check(item)
    }

    pub fn clear(&mut self) {
        self.inner.clear()
    }
}