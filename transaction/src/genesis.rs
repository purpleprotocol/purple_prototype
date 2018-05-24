use account::{Balance, Address};
use itc::Stamp;
use purple_crypto::{Hash, Signature};

pub struct Genesis {
    balance: Balance,
    address: Address,
    hash: Option<Hash>,
    signature: Option<Signature>,
    stamp: Stamp
}