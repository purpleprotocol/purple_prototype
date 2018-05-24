use account::{Balance, Address};
use itc::Stamp;
use purple_crypto::{Hash, Signature};

pub struct Send {
    previous_hash: Hash,
    referenced_hash: Hash,
    destination: Address,
    balance: Balance,
    hash: Option<Hash>,
    signature: Option<Signature>,
    address: Address,
    stamp: Stamp
}