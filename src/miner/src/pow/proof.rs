use crate::verify::PROOF_SIZE;
use byteorder::{WriteBytesExt, LittleEndian};
use crypto::Hash;
use std::fmt;
use std::iter;
use rand::*;
use bitvec::Bits;

const MIN_EDGE_BITS: u8 = 24;

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
    }
}