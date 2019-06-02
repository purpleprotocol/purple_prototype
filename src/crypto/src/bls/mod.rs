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

use multi_sigs::bls::common::{SigKey, VerKey, Keypair};
use multi_sigs::bls::simple::Signature;

pub mod pkey;
pub mod skey;
pub mod signature;

use pkey::*;
use skey::*;
use crate::bls::signature::*;

pub fn gen_bls_keypair() -> (BlsPkey, BlsSkey) {
    let keypair = Keypair::new(None);
    (BlsPkey::new(keypair.ver_key), BlsSkey::new(keypair.sig_key))
}

pub fn bls_sign(message: &[u8], skey: &BlsSkey) -> BlsSig {
    let sig = Signature::new(message, &skey.0);
    BlsSig::new(sig)
}

pub fn bls_verify(message: &[u8], sig: &BlsSig, pkey: &BlsPkey) -> bool {
    sig.0.verify(message, &pkey.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let (pk, sk) = gen_bls_keypair();
        let (pk2, _)=  gen_bls_keypair();
        let message = b"test_message";
        let message2 = b"test_message2";
        let sig = bls_sign(message, &sk);

        assert!(bls_verify(message, &sig, &pk));
        assert!(!bls_verify(message, &sig, &pk2));
        assert!(!bls_verify(message2, &sig, &pk));
    }
}