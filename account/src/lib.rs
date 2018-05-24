#[derive(Debug)]
pub struct Balance {
    value: String
}

#[derive(Debug)]
pub struct Address([u8; 32]);