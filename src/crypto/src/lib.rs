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

#![feature(extern_prelude)]

#[macro_use]
extern crate serde_derive;

extern crate rlp;
extern crate hashdb;
extern crate rand;
extern crate hex;
extern crate blake2;
extern crate rust_sodium;
extern crate quickcheck;

pub use hash::*;
pub use signature::*;
pub use blake_hasher::*;
pub use rust_sodium::crypto::sign::{gen_keypair, PublicKey, SecretKey};

mod hash;
mod signature;
mod blake_hasher;

use rust_sodium::crypto::sign::{sign_detached, verify_detached};

pub fn sign(message: &[u8], skey: SecretKey) -> Signature {
    let sig = sign_detached(message, &skey);
    Signature::new(&sig.0)
}

pub fn verify(message: &[u8], signature: Signature, pkey: PublicKey) -> bool {
    verify_detached(&signature.inner(), message, &pkey)
}

#[derive(Clone, Debug)]
pub struct Identity(PublicKey, SecretKey);

impl Identity {
    pub fn new() -> Identity {
        let (pk, sk) = gen_keypair();
        Identity(pk, sk)
    }

    pub fn pkey(&self) -> &PublicKey {
        &self.0
    }

    pub fn skey(&self) -> &SecretKey {
        &self.1
    }
}

use quickcheck::Arbitrary;

impl Arbitrary for Identity {
    fn arbitrary<G : quickcheck::Gen>(_g: &mut G) -> Identity {
        Identity::new()
    }
}