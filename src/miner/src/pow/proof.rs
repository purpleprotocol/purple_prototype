use crate::verify::PROOF_SIZE;
use bin_tools::*;
use bitvec::Bits;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use crypto::Hash;
use rand::*;
use std::fmt;
use std::io::Cursor;
use std::iter;

pub const MIN_EDGE_BITS: u8 = 24;

#[derive(Clone, PartialOrd, PartialEq)]
pub struct Proof {
    /// Power of 2 used for the size of the cuckoo graph
    pub edge_bits: u8,
    /// The nonces
    pub nonces: Vec<u64>,
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cuckoo{}(", self.edge_bits)?;
        for (i, val) in self.nonces[..].iter().enumerate() {
            write!(f, "{:x}", val)?;
            if i < self.nonces.len() - 1 {
                write!(f, " ")?;
            }
        }
        write!(f, ")")
    }
}

impl Eq for Proof {}

impl Proof {
    /// Builds a proof with provided nonces and edge_bits
    pub fn new(mut in_nonces: Vec<u64>, edge_bits: u8) -> Proof {
        in_nonces.sort_unstable();
        Proof {
            edge_bits,
            nonces: in_nonces,
        }
    }

    #[cfg(feature = "test")]
    /// A proof that will always validate. Only used for testing.
    pub fn test_proof(proof_size: usize) -> Proof {
        Proof {
            edge_bits: 0,
            nonces: vec![0; proof_size],
        }
    }

    /// Builds a proof with all bytes zeroed out
    pub fn zero(proof_size: usize) -> Proof {
        Proof {
            edge_bits: MIN_EDGE_BITS,
            nonces: vec![0; proof_size],
        }
    }

    /// Builds a proof with random POW data,
    /// needed so that tests that ignore POW
    /// don't fail due to duplicate hashes
    pub fn random(proof_size: usize) -> Proof {
        let edge_bits = MIN_EDGE_BITS;
        let nonce_mask = (1 << edge_bits) - 1;
        let mut rng = thread_rng();
        // force the random num to be within edge_bits bits
        let mut v: Vec<u64> = iter::repeat(())
            .map(|()| (rng.gen::<u32>() & nonce_mask) as u64)
            .take(proof_size)
            .collect();
        v.sort_unstable();
        Proof {
            edge_bits: MIN_EDGE_BITS,
            nonces: v,
        }
    }

    /// Returns the proof size
    pub fn proof_size(&self) -> usize {
        self.nonces.len()
    }

    pub fn hash(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 * PROOF_SIZE + 1);
        buf.write_u8(self.edge_bits).unwrap();

        for n in self.nonces.iter() {
            buf.write_u64::<LittleEndian>(*n).unwrap();
        }

        crypto::hash_slice(&buf)
    }

    /// The difficulty is the number of leading
    /// 0 bits found in the hash of the proof.
    pub fn to_difficulty(&self) -> u8 {
        let difficulty = {
            let mut difficulty = 0;
            let hash = self.hash();

            // Traverse hash bytes
            for byte in hash.0.iter() {
                let mut stop = false;

                // Traverse bits
                for i in 0..8 {
                    if byte.get(i) {
                        stop = true;
                        break;
                    }

                    difficulty += 1;
                }

                if stop {
                    break;
                }
            }

            difficulty
        };

        max!(1, difficulty)
    }

    /// Serializes the proof to a binary format
    ///
    /// Binary Structure:
    /// 1) Edge bits - 8bits
    /// 2) Proof     - 64bits * PROOF_SIZE
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 8 * PROOF_SIZE);

        buf.extend_from_slice(&[self.edge_bits]);

        for nonce in self.nonces.iter() {
            buf.extend_from_slice(&encode_be_u64!(*nonce));
        }

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Proof, &'static str> {
        if bytes.len() != 1 + 8 * PROOF_SIZE {
            return Err("Invalid slice length");
        }

        let mut cursor = Cursor::new(bytes);
        let mut nonces = Vec::with_capacity(PROOF_SIZE);
        let edge_bits = cursor.read_u8().unwrap();

        for _ in 0..PROOF_SIZE {
            if let Ok(result) = cursor.read_u64::<BigEndian>() {
                nonces.push(result);
            } else {
                return Err("Bad nonce");
            };
        }

        Ok(Proof::new(nonces, edge_bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    quickcheck! {
        fn it_maps_proof_to_difficulty() -> bool {
            let proof = Proof::random(PROOF_SIZE);
            let difficulty = proof.to_difficulty();
            true
        }

        fn it_serializes_and_deserializes_proof() -> bool {
            let proof = Proof::random(PROOF_SIZE);
            Proof::from_bytes(&proof.to_bytes()).unwrap() == proof
        }
    }
}
