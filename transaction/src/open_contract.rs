use account::{Balance, Address};
use itc::Stamp;
use purple_crypto::{Hash, Signature};

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