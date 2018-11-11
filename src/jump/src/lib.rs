extern crate crypto;

use crypto::*;

extern {
    fn JumpConsistentHash(key: u64, num: i64) -> i64;
}

pub fn jump_bytes(key: &[u8], buckets: i64) -> i64 {
    let key_hash: Vec<u8> = hash_slice(key).to_vec();
    let key: u64 = bytes_to_uint(&key_hash);

    jump_ch(key, buckets)
}

pub fn jump_ch(key: u64, buckets: i64) -> i64 {
    unsafe { JumpConsistentHash(key, buckets) }
}

// Convert bytes to uint assuming they are in big endian order
fn bytes_to_uint(bin: &[u8]) -> u64 {
    let mut result: u64 = 0;

    for byte in bin {
        result = result.wrapping_shl(8).wrapping_add((byte & 0xff) as u64);
    }

    result
}

#[test]
fn jump_bytes_test() {
    let key = b"The quick brown fox jumps over the lazy dog";
    let hash = hash_slice(key).to_vec();
    let key_uint = bytes_to_uint(&hash);

    let result1 = jump_bytes(key, 10);
    let result2 = jump_ch(key_uint, 10);

    assert_eq!(result1, result2);
}