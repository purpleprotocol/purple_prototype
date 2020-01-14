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

#[macro_use]
extern crate serde_derive;

pub extern crate crc32fast;
pub use blake_hasher::*;
pub use hash::*;
pub use short_hash::*;
pub use node_id::*;
pub use rust_base58::base58::*;
pub use rust_sodium::crypto::aead;
pub use rust_sodium::crypto::aead::Nonce;
pub use rust_sodium::crypto::kx::{
    client_session_keys as client_sk, gen_keypair as gen_kx_keypair,
    server_session_keys as server_sk, PublicKey as KxPublicKey, SecretKey as KxSecretKey,
    SessionKey,
};
pub use rust_sodium::crypto::sign::{gen_keypair, PublicKey, SecretKey};
pub use signature::*;
use rust_sodium::crypto::sign::{keypair_from_seed, Seed};


mod blake_hasher;
mod hash;
mod short_hash;
mod node_id;
mod signature;

use rust_sodium::crypto::sign::{sign_detached, verify_detached};

pub fn sign(message: &[u8], skey: &SecretKey) -> Signature {
    let sig = sign_detached(message, skey);
    Signature::new(&sig.0)
}

pub fn verify(message: &[u8], signature: &Signature, pkey: &PublicKey) -> bool {
    verify_detached(&signature.inner(), message, pkey)
}

pub fn seal(message: &[u8], key: &SessionKey) -> (Vec<u8>, Nonce) {
    let n = aead::gen_nonce();
    let key = aead::Key::from_slice(&key.0).unwrap();
    let ciphertext = aead::seal(message, None, &n, &key);

    (ciphertext, n)
}

pub fn open(ciphertext: &[u8], key: &SessionKey, nonce: &Nonce) -> Result<Vec<u8>, ()> {
    let key = aead::Key::from_slice(&key.0).unwrap();

    match aead::open(ciphertext, None, nonce, &key) {
        Ok(result) => Ok(result),
        _ => Err(()),
    }
}

pub fn gen_keypair_from_seed(seed: &[u8]) -> (PublicKey, SecretKey) {
    let hashed_seed = hash_slice(seed);
    let seed = Seed(hashed_seed.0);
    keypair_from_seed(&seed)
}

/// Generates a random array of bytes of the given length.
pub fn gen_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
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
    fn arbitrary<G: quickcheck::Gen>(_g: &mut G) -> Identity {
        Identity::new()
    }
}
