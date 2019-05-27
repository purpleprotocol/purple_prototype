use crypto::Hash;
use std::fmt;
use std::iter;
use rand::*;

const MIN_EDGE_BITS: u8 = 24;

/// A Cuckaroo Cycle proof of work, consisting of the edge_bits to get the graph
/// size (i.e. the 2-log of the number of edges) and the nonces
/// of the graph solution. While being expressed as u64 for simplicity,
/// nonces a.k.a. edge indices range from 0 to (1 << edge_bits) - 1
///
/// The hash of the `Proof` is the hash of its packed nonces when serializing
/// them at their exact bit size. The resulting bit sequence is padded to be
/// byte-aligned.
///
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
        unimplemented!();
    } 

    /// TODO: Re-write this
	pub fn to_difficulty(&self, scale: u64) -> u64 {
		max!(1, self.hash().to_u64())
	}
}