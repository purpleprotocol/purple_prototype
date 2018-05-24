extern crate blake2;

use blake2::{Blake2s, Digest};

pub struct Hash([u8; 32]);
pub struct Pkey([u8; 32]);
pub struct Skey([u8; 64]);
pub struct Signature([u8; 64]);

pub fn hash_slice(val: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s::new();

    hasher.input(&val);
    hasher.result().as_slice().to_vec()
}

// pub fn sign() -> Signature {

// }

// pub fn verify() -> bool {

// }

#[cfg(test)]
mod tests {
    extern crate hex;
    use super::*;

    #[test]
    fn hash() {
        let hash1   = hash_slice(b"");
        let hash2   = hash_slice(b"The quick brown fox jumps over the lazy dog");
        let result1 = hex::encode(hash1.as_slice());
        let result2 = hex::encode(hash2.as_slice());
        
        assert_eq!(result1, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
        assert_eq!(result2, "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812");
    }
}