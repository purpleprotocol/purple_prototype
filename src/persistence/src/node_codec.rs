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

  This is a modified implementation of Parity's `NodeCodec`:
  https://github.com/paritytech/parity-ethereum/blob/c313039526269f4690f6f3ea006b32f2d81ee6ab/util/patricia-trie-ethereum/src/rlp_node_codec.rs
*/

use patricia_trie::node::Node;
use patricia_trie::{NibbleSlice, NodeCodec, ChildReference};
use hashdb::Hasher;
use Hasher as DbHasher;
use crypto::Hash;
use rlp::{DecoderError, Rlp, RlpStream, Prototype};
use elastic_array::ElasticArray128;

pub struct Codec;

impl NodeCodec<Hash> for Codec {
    type Error = DecoderError;
    const HASHED_NULL_NODE: Hash = Hash::NULL;

    fn decode(data: &[u8]) -> ::std::result::Result<Node, Self::Error> {
		let r = Rlp::new(data);

		match r.prototype()? {
			Prototype::List(2) => match NibbleSlice::from_encoded(r.at(0)?.data()?) {
				(slice, true)  => Ok(Node::Leaf(slice, r.at(1)?.data()?)),
				(slice, false) => Ok(Node::Extension(slice, r.at(1)?.as_raw())),
			},
			// branch - first 16 are nodes, 17th is a value (or empty).
			Prototype::List(17) => {
				let mut nodes = [&[] as &[u8]; 16];
				for i in 0..16 {
					nodes[i] = r.at(i)?.as_raw();
				}
				Ok(Node::Branch(nodes, if r.at(16)?.is_empty() { None } else { Some(r.at(16)?.data()?) }))
			},
			// an empty branch index.
			Prototype::Data(0) => Ok(Node::Empty),
			// something went wrong.
			_ => Err(DecoderError::Custom("Rlp is not valid."))
		}
	}

	fn try_decode_hash(data: &[u8]) -> Option<Hash> {
		let r = Rlp::new(data);

		if r.is_data() && r.size() == DbHasher::LENGTH {
			Some(r.as_val().unwrap())
		} else {
			None
		}
	}
    
    fn is_empty_node(data: &[u8]) -> bool {
		Rlp::new(data).is_empty()
	}

    fn empty_node() -> Vec<u8> {
        let mut stream = RlpStream::new();
        
        stream.append_empty_data();
        stream.drain()
    }

    fn leaf_node(partial: &[u8], value: &[u8]) -> Vec<u8> {
        let mut stream = RlpStream::new_list(2);

        stream.append(&partial);
        stream.append(&value);
		stream.drain()
    }

    fn ext_node(partial: &[u8], child_ref: ChildReference<Hash>) -> Vec<u8> {
        let mut stream = RlpStream::new_list(2);
        
        stream.append(&partial);
        
        match child_ref {
            ChildReference::Hash(h) => stream.append(&h),
            ChildReference::Inline(inline_data, len) => {
                let bytes = &AsRef::<[u8]>::as_ref(&inline_data)[..len];
                stream.append_raw(bytes, 1)
            },
        };

        stream.drain()
	}

	fn branch_node<I>(children: I, value: Option<ElasticArray128<u8>>) -> Vec<u8>
	    where I: IntoIterator<Item=Option<ChildReference<Hash>>>
    {
        let mut stream = RlpStream::new_list(17);
        
        for child_ref in children {
            match child_ref {
                Some(c) => match c {
                    ChildReference::Hash(h) => stream.append(&h),
                    ChildReference::Inline(inline_data, len) => {
                        let bytes = &AsRef::<[u8]>::as_ref(&inline_data)[..len];
                        stream.append_raw(bytes, 1)
                    },
                },
                None => stream.append_empty_data()
            };
        }

        if let Some(value) = value {
            stream.append(&&*value);
        } else {
            stream.append_empty_data();
        }
        
        stream.drain()
    }
}