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

use crypto::{PublicKey, Signature};
use quickcheck::Arbitrary;
use rand::Rng;
use ShareMap;

const SIG_TYPE: u8 = 2;

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct MultiSig(Vec<Signature>);

impl MultiSig {
    pub fn from_sig(signature: Signature) -> MultiSig {
        let inner: Vec<Signature> = vec![signature];
        MultiSig(inner)
    } 

    pub fn verify(&self, message: &[u8], required_keys: u8, pkeys: &[PublicKey]) -> bool {
        if required_keys < 2 {
            panic!("The required keys parameter cannot be less than 2!")
        }

        if pkeys.len() < required_keys as usize {
            panic!("The length of the given public keys list is smaller than the required keys!")
        }
        
        let mut validated_keys: u8 = 0;
        
        for sig in &self.0 {
            let mut valid = false;

            // Check signature against all public keys
            for pk in pkeys {
                if crypto::verify(message, sig.clone(), *pk) {
                    valid = true;
                    break;
                }
            } 

            if !valid {
                return false;
            }

            validated_keys += 1;

            if validated_keys == required_keys {
                return true;
            }
        }

        false
    }

    pub fn verify_shares(&self, message: &[u8], required_percentile: u8, share_map: ShareMap) -> bool {
        let mut signed_ratio: u8 = 0;

        for sig in &self.0 {
            // Find a matching address in the share map for the signature
            match share_map.find_signer(message, sig.clone()) {
                Some(sh_ratio) => signed_ratio += sh_ratio,
                None           => return false
            }

            if signed_ratio >= required_percentile {
                return true;
            }
        }

        false
    }

    pub fn append_sig(&mut self, signature: Signature) {
        self.0.push(signature);
    }

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

                for bytes in rlp_decoded.clone() {
                    if bytes.len() == 65 {
                        let mut sig = [0; 65];
                        sig.copy_from_slice(&bytes);

                        match Signature::from_bytes(&sig) {
                            Ok(sig) => result.push(sig),
                            Err(_)  => return Err("Invalid signature") 
                        };
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

impl Arbitrary for MultiSig {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> MultiSig {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(1, 255);
        let signatures: Vec<Signature> = (0..random).map(|_| Arbitrary::arbitrary(g)).collect();

        MultiSig(signatures)
    }
}