use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

#[derive(Hashable, Signable, Serializable)]
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