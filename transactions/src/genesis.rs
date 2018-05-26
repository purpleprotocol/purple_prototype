use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use account::{Balance, Address};
use purple_crypto::{Signature, Hash};
use itc::Stamp;
use traits::*;

#[derive(Hashable, Signable, Serialize, Deserialize)]
pub struct Genesis {
    balance: Balance,
    address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    stamp: Stamp
}