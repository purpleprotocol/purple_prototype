use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

#[derive(Hashable, Signable, Serializable)]
pub struct Receive {
    previous_hash: Hash,
    referenced_hash: Hash,
    balance: Balance,
    hash: Option<Hash>,
    signature: Option<Signature>,
    address: Address,
    approver: Address,
    source: Hash,
    stamp: Stamp
}