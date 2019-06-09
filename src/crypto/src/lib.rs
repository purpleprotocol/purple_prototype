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

#[macro_use]
extern crate serde_derive;

extern crate digest;
extern crate ed25519_dalek;
extern crate blake2;
extern crate hashdb;
extern crate hex;
extern crate merkle_light;
extern crate quickcheck;
extern crate rand;
extern crate rlp;
extern crate byteorder;
extern crate crc32fast;
extern crate rust_base58;
extern crate rust_sodium;

pub use blake_hasher::*;
pub use hash::*;
pub use rust_base58::base58::*;
pub use ed25519_dalek::{PublicKey, SecretKey, ExpandedSecretKey};
pub use rust_sodium::crypto::kx::{
    gen_keypair as gen_kx_keypair, 
    PublicKey as KxPublicKey, 
    SecretKey as KxSecretKey, 
    SessionKey,
    client_session_keys as client_sk,
    server_session_keys as server_sk,
};
pub use signature::*;
use rand::Rng;
use rand::OsRng;
use ed25519_dalek::Keypair;
use blake2::Blake2b;

mod blake_hasher;
mod hash;
mod signature;

pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let mut csprng: OsRng = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate::<Blake2b, _>(&mut csprng);
    
    (keypair.public, keypair.secret)
}

/// Signs a message with an un-expanded secret key
pub fn sign(message: &[u8], skey: &SecretKey, pkey: &PublicKey) -> Signature {
    let skey = skey.expand::<Blake2b>();
    sign_expanded(message, &skey, pkey)
}

/// Signs a message with an expanded secret key
pub fn sign_expanded(message: &[u8], skey: &ExpandedSecretKey, pkey: &PublicKey) -> Signature {
    let sig = skey.sign::<Blake2b>(message, pkey);
    Signature(sig)
}

pub fn verify(message: &[u8], signature: &Signature, pkey: &PublicKey) -> bool {
    pkey.verify::<Blake2b>(message, &signature.0).is_ok()
}

#[derive(Debug)]
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