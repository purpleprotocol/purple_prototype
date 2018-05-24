use account::{Balance, Address};
use itc::Stamp;
use purple_crypto::{Hash, Signature};

pub struct Return {
    previous_hash: Hash,
    referenced_hash: Hash,
    balance: Balance,
    hash: Option<Hash>,
    signature: Option<Signature>,
    address: Address,
    approver: Address,
    source: Hash,
    output: String, // TODO: Change this
    stamp: Stamp
}