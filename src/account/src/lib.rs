#[macro_use] extern crate serde_derive;

#[derive(Serialize, Deserialize, Debug)]
pub struct Balance {
    value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Address([u8; 32]);