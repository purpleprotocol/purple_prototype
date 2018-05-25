use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

pub struct Parameters {
    params: Vec<String>,
    count: usize
}

#[derive(Hashable, Signable, Serializable)]
pub struct Call {
    previous_hash: Hash,
    referenced_hash: Hash,
    hash: Option<Hash>,
    signature: Option<Signature>,
    address: Address,
    destination: Address,
    balance: Balance,
    params: Parameters,
    stamp: Stamp
}