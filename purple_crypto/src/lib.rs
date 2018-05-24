extern crate blake2;
extern crate rust_sodium;

use rust_sodium::crypto::sign;

pub use hash::*;
pub use rust_sodium::crypto::sign::{
    PublicKey, 
    SecretKey, 
    Signature,
    gen_keypair,
    sign_detached,
    verify_detached
};

mod hash;