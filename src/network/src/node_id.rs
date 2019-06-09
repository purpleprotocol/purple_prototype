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

use crypto::{Identity, PublicKey};
use quickcheck::Arbitrary;
use rand::Rng;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn new(bin: [u8; 32]) -> NodeId {
        NodeId(bin)
    }

    pub fn from_pkey(pk: PublicKey) -> NodeId {
        let pk = pk.to_bytes();
        let mut result = [0; 32];
        result.copy_from_slice(&pk);

        NodeId(result)
    }

    pub fn to_pkey(&self) -> PublicKey {
        PublicKey::from_bytes(&self.0).unwrap()
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NodeId({})", hex::encode(self.0))
    }
}

impl Arbitrary for NodeId {
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> NodeId {
        let id = Identity::new();
        NodeId::from_pkey(id.pkey().clone())
    }
}
