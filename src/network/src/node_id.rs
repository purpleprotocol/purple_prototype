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

use crypto::PublicKey;
use quickcheck::Arbitrary;
use rand::Rng;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub PublicKey);

impl NodeId {
    pub fn new(bin: [u8; 32]) -> NodeId {
        NodeId(PublicKey(bin))
    }

    pub fn from_pkey(pk: PublicKey) -> NodeId {
        NodeId(pk)
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
