use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

pub struct Parameters {
    params: Vec<String>,
    count: usize
}

#[derive(Hashable, Signable, Serialize, Deserialize)]
pub struct Call {
    previous_hash: Hash,
    referenced_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    address: Address,
    destination: Address,
    balance: Balance,
    params: Parameters,
    stamp: Stamp
}