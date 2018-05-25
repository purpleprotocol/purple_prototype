use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

#[derive(Hashable, Signable, Serializable)]
pub struct Genesis {
    balance: Balance,
    address: Address,
    hash: Option<Hash>,
    signature: Option<Signature>,
    stamp: Stamp
}