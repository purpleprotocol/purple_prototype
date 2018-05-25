use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

#[derive(Hashable, Signable, Serializable)]
pub struct OpenContract {
    source: Hash,
    address: Address,
    balance: Balance,
    hash: Option<Hash>,
    signature: Option<Signature>,
    src: String,
    state: String, // TODO: change to trie
    stamp: Stamp
}