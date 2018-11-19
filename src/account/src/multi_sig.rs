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

use crypto::Signature;
use SigExtern;

const SIG_TYPE: u8 = 2;

#[derive(Serialize, Deserialize, Debug)]
pub struct MultiSig(Vec<Signature>);

impl MultiSig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(self.0.len() + 1);

        for sig in self.0.iter() {
            sigs.push(sig.to_bytes());
        }

        let mut result: Vec<u8> = rlp::encode_list::<Vec<u8>, _>(&sigs);
        let mut final_result: Vec<u8> = vec![SIG_TYPE];

        final_result.append(&mut result);
        final_result
    }

    pub fn from_bytes(bin: &[u8]) -> Result<MultiSig, &'static str> {
        let bin_vec = bin.to_vec();
        let (head, tail) = bin_vec.split_at(1);

        match head {
            [2] => {
                let rlp_decoded: Vec<Vec<u8>> = rlp::decode_list(&tail);
                let mut result: Vec<Signature> = Vec::with_capacity(rlp_decoded.len());

                for bytes in rlp_decoded {
                    if bytes.len() == 64 {
                        let mut sig = [0; 64];
                        sig.copy_from_slice(&bytes);

                        result.push(Signature(sig));
                    } else {
                        return Err("Invalid signature length");
                    }
                }

                Ok(MultiSig(result))
            },
            _ => {
                Err("Invalid signature type")
            }
        }
    }
}