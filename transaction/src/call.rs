use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;

pub struct Parameters {
    params: Vec<String>,
    count: usize
}

pub struct Call {
    previous_hash: Hash,
    referenced_hash: Hash,
    hash: Hash,
    address: Address,
    destination: Address,
    balance: Balance,
    signature: Signature,
    params: Parameters,
    stamp: Stamp
}