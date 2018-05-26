use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

#[derive(Hashable, Signable, Serialize, Deserialize)]
pub struct OpenContract {
    source: Hash,
    address: Address,
    balance: Balance,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    src: String,
    state: String, // TODO: change to trie
    stamp: Stamp
}