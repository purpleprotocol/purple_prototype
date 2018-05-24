use account::{Balance, Address};
use itc::Stamp;

#[derive(Clone, Debug)]
pub struct Genesis {
    balance: Balance,
    address: Address,
    hash: [u8; 32], // TODO: Change this with type wrapper
    signature: [u8; 32], // TODO: Change this with type wrapper
    stamp: Stamp
}