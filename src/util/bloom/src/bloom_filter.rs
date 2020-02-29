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
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::Cursor;

/// The size of an item in the bloom filter in bytes
pub const ITEM_SIZE: usize = 8;

pub struct Bloom {
    inner: BloomFilter<[u8; ITEM_SIZE]>,
    bitmap_size: u32,
    items_count: u32,
}

impl Bloom {
    pub fn new(bitmap_size: u32, items_count: u32) -> Bloom {
        Bloom {
            inner: BloomFilter::new(bitmap_size as usize, items_count as usize),
            bitmap_size,
            items_count,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity((self.bitmap_size as usize) + 4 + 4 + 8 + 4 + (8 * 4));
        let hash_functions = self.inner.number_of_hash_functions();
        let sip_keys = self.inner.sip_keys();
        let sip1 = sip_keys[0].0;
        let sip2 = sip_keys[0].1;
        let sip3 = sip_keys[1].0;
        let sip4 = sip_keys[1].1;

        buf.write_u32::<BigEndian>(self.bitmap_size).unwrap();
        buf.write_u32::<BigEndian>(self.items_count).unwrap();
        buf.write_u32::<BigEndian>(hash_functions).unwrap();
        buf.write_u64::<BigEndian>(sip1).unwrap();
        buf.write_u64::<BigEndian>(sip2).unwrap();
        buf.write_u64::<BigEndian>(sip3).unwrap();
        buf.write_u64::<BigEndian>(sip4).unwrap();
        buf.extend_from_slice(&self.inner.bitmap());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Bloom, BloomErr> {
        let mut rdr = Cursor::new(bytes.to_vec());

        let bitmap_size = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(BloomErr::ParseError);
        };

        rdr.set_position(4);

        let items_count = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(BloomErr::ParseError);
        };

        rdr.set_position(8);

        let hash_functions = if let Ok(result) = rdr.read_u32::<BigEndian>() {
            result
        } else {
            return Err(BloomErr::ParseError);
        };

        rdr.set_position(12);

        let sip1 = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(BloomErr::ParseError);
        };

        rdr.set_position(20);

        let sip2 = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(BloomErr::ParseError);
        };

        rdr.set_position(28);

        let sip3 = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(BloomErr::ParseError);
        };

        rdr.set_position(36);

        let sip4 = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err(BloomErr::ParseError);
        };

        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..44).collect();

        let bitmap = if buf.len() == bitmap_size as usize {
            buf
        } else {
            return Err(BloomErr::ParseError);
        };

        let sip_keys = [(sip1, sip2), (sip3, sip4)];

        Ok(Bloom {
            inner: BloomFilter::from_existing(
                &bitmap,
                (bitmap_size as u64) * 8,
                hash_functions,
                sip_keys,
            ),
            bitmap_size,
            items_count,
        })
    }
}

impl Clone for Bloom {
    fn clone(&self) -> Bloom {
        let sip_keys = self.inner.sip_keys();
        let hash_functions = self.inner.number_of_hash_functions();
        let bitmap_size = self.bitmap_size;
        let items_count = self.items_count;

        Bloom {
            inner: BloomFilter::from_existing(
                &self.inner.bitmap(),
                (bitmap_size as u64) * 8,
                hash_functions,
                sip_keys,
            ),
            bitmap_size,
            items_count,
        }
    }
}

impl PartialEq for Bloom {
    fn eq(&self, other: &Self) -> bool {
        let sip_keys = self.inner.sip_keys();
        let hash_functions = self.inner.number_of_hash_functions();
        let bitmap_size = self.bitmap_size;
        let items_count = self.items_count;
        let other_sip_keys = self.inner.sip_keys();
        let other_hash_functions = self.inner.number_of_hash_functions();
        let other_bitmap_size = self.bitmap_size;
        let other_items_count = self.items_count;

        sip_keys == other_sip_keys
            && hash_functions == other_hash_functions
            && bitmap_size == other_bitmap_size
            && items_count == other_items_count
            && self.inner.bitmap() == other.inner.bitmap()
    }
}

impl fmt::Debug for Bloom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bloom(NaN)")
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for Bloom {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Bloom {
        use bin_tools::*;
        let mut bloom = Bloom::new(100 * (ITEM_SIZE as u32), 100);

        // Insert 100 random values
        for _ in 0..100 {
            let v: u64 = Arbitrary::arbitrary(g);
            let v_le = encode_le_u64!(v);

            let mut v = [0; ITEM_SIZE];
            v.copy_from_slice(&v_le);

            bloom.set(&v);
        }

        bloom
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    quickcheck! {
        fn serialize_deserialize(bloom: Bloom) -> bool {
            bloom == Bloom::from_bytes(&Bloom::to_bytes(&bloom)).unwrap()
        }
    }
}
