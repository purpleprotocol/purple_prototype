use account::{Balance, Address};
use itc::Stamp;
use purple_crypto::{Hash, Signature};

pub struct Open {
    source: Hash,
    address: Address,
    balance: Balance,
    hash: Option<Hash>,
    signature: Option<Signature>,
    stamp: Stamp
}