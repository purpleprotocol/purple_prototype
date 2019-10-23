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

use crate::PublicKey;
use quickcheck::Arbitrary;
use rand::Rng;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub PublicKey);

impl NodeId {
    pub fn new(bin: [u8; 32]) -> NodeId {
        NodeId(PublicKey(bin))
    }

    pub fn from_pkey(pk: PublicKey) -> NodeId {
        NodeId(pk)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<NodeId, &'static str> {
        if bytes.len() != 32 {
            return Err("Invalid slice length! Expected 32 bytes!");
        }

        let mut inner = [0; 32];
        inner.copy_from_slice(bytes);

        Ok(NodeId(PublicKey(inner)))
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NodeId({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Arbitrary for NodeId {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> NodeId {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen_range(1, 255)).collect();

        let mut result = [0; 32];
        result.copy_from_slice(&bytes);

        NodeId(PublicKey(result))
    }

    fn shrink(&self) -> Box<Iterator<Item = Self>> {
        Box::new((&(&self.0).0).to_vec().shrink().map(|p| {
            let mut result = [0; 32];
            result.copy_from_slice(&p);

            NodeId(PublicKey(result))
        }))
    }
}
