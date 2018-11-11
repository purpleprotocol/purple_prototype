use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use account::{Balance, Address};
use crypto::{Signature, Hash};
use causality::Stamp;
use traits::*;

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
    stamp: Stamp
}