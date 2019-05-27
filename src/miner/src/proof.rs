/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.

  Parts of this file were adapted from the following file:
  https://github.com/mimblewimble/grin-miner/blob/master/cuckoo-miner/src/miner/consensus.rs
*/

// use crypto::Hash;
// use blake2_rfc::blake2b::Blake2b;
// use std::cmp::{max, min};
// use std::fmt;
// use byteorder::{BigEndian, ByteOrder};

// // constants from grin
// const DEFAULT_MIN_EDGE_BITS: u8 = 31;
// const SECOND_POW_EDGE_BITS: u8 = 29;
// const PROOF_SIZE: usize = 42;
// const BLOCK_TIME_SEC: u64 = 60;

// const HOUR_HEIGHT: u64 = 3600 / BLOCK_TIME_SEC;
// const DAY_HEIGHT: u64 = 24 * HOUR_HEIGHT;
// const WEEK_HEIGHT: u64 = 7 * DAY_HEIGHT;
// const YEAR_HEIGHT: u64 = 52 * WEEK_HEIGHT;

// const BASE_EDGE_BITS: u8 = 24;

// /// Compute weight of a graph as number of siphash bits defining the graph
// /// Must be made dependent on height to phase out smaller size over the years
// /// This can wait until end of 2019 at latest
// pub fn graph_weight(height: u64, edge_bits: u8) -> u64 {
// 	let mut xpr_edge_bits = edge_bits as u64;

// 	let bits_over_min = edge_bits.saturating_sub(DEFAULT_MIN_EDGE_BITS);
// 	let expiry_height = (1 << bits_over_min) * YEAR_HEIGHT;
// 	if height >= expiry_height {
// 		xpr_edge_bits = xpr_edge_bits.saturating_sub(1 + (height - expiry_height) / WEEK_HEIGHT);
// 	}

// 	(2 << (edge_bits - BASE_EDGE_BITS) as u64) * xpr_edge_bits
// }

// /// The difficulty is defined as the maximum target divided by the block hash.
// #[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
// pub struct Difficulty {
// 	num: u64,
// }

// impl Difficulty {
// 	/// Convert a `u32` into a `Difficulty`
// 	pub fn from_num(num: u64) -> Difficulty {
// 		// can't have difficulty lower than 1
// 		Difficulty { num: max(num, 1) }
// 	}

// 	/// Computes the difficulty from a hash. Divides the maximum target by the
// 	/// provided hash and applies the Cuck(at)oo size adjustment factor (see
// 	/// https://lists.launchpad.net/mimblewimble/msg00494.html).
// 	fn from_proof_adjusted(height: u64, proof: &Proof) -> Difficulty {
// 		// scale with natural scaling factor
// 		Difficulty::from_num(proof.scaled_difficulty(graph_weight(height, proof.edge_bits)))
// 	}

// 	/// unscaled proof
// 	fn from_proof_unscaled(proof: &Proof) -> Difficulty {
// 		Difficulty::from_num(proof.scaled_difficulty(1u64))
// 	}

// 	/// Same as `from_proof_adjusted` but instead of an adjustment based on
// 	/// cycle size, scales based on a provided factor. Used by dual PoW system
// 	/// to scale one PoW against the other.
// 	fn from_proof_scaled(proof: &Proof, scaling: u32) -> Difficulty {
// 		// Scaling between 2 proof of work algos
// 		Difficulty::from_num(proof.scaled_difficulty(scaling as u64))
// 	}

// 	/// Converts the difficulty into a u64
// 	pub fn to_num(&self) -> u64 {
// 		self.num
// 	}
// }

// impl fmt::Display for Difficulty {
// 	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
// 		write!(f, "{}", self.num)
// 	}
// }

// struct BitVec {
// 	bits: Vec<u8>,
// }

// impl BitVec {
// 	/// Number of bytes required to store the provided number of bits
// 	fn bytes_len(bits_len: usize) -> usize {
// 		(bits_len + 7) / 8
// 	}

// 	fn new(bits_len: usize) -> BitVec {
// 		BitVec {
// 			bits: vec![0; BitVec::bytes_len(bits_len)],
// 		}
// 	}

// 	fn set_bit_at(&mut self, pos: usize) {
// 		self.bits[pos / 8] |= 1 << (pos % 8) as u8;
// 	}
// }

// #[cfg(test)]
// mod tests {
// 	use super::*;

// 	#[test]
// 	fn proof_hash() {
// 		let mut in_nonces: Vec<u64> = [0u64; 42].to_vec(); 
// 		let proof = Proof::new(in_nonces.clone(), DEFAULT_MIN_EDGE_BITS);
// 		let hash_str = format!("{:?}", proof.hash());
// 		assert_eq!(&hash_str, "Hash(5fa5af8a4c86dd0ef5e78a59e2de015e1cbd7af8c7830074885f3ccb61608bc5)");

// 		in_nonces[41] = 23402320128419283;
// 		in_nonces[11] = 81239481234781924;
// 		let proof = Proof::new(in_nonces.clone(), DEFAULT_MIN_EDGE_BITS);
// 		let hash_str = format!("{:?}", proof.hash());
// 		assert_eq!(&hash_str, "Hash(378594bac9a46cc89c3b7c5fdfaae578dc2546de69b146d7d56135172d1607e1)");

// 		for i in in_nonces.iter_mut() {
// 			*i = std::u64::MAX;
// 		}
// 		let proof = Proof::new(in_nonces.clone(), DEFAULT_MIN_EDGE_BITS);
// 		let hash_str = format!("{:?}", proof.hash());
// 		assert_eq!(&hash_str, "Hash(99f04aafcbc1ab55571f4cf075bdb9a7fecc8c7a22b29fef574f9f8248e59b87)");
// 	}

// 	#[test]
// 	fn proof_difficulty() {
// 		let mut in_nonces: Vec<u64> = [0u64; 42].to_vec();
// 		let proof = Proof::new(in_nonces.clone(), DEFAULT_MIN_EDGE_BITS);
// 		let difficulty = proof.to_difficulty(20, 1);
// 		println!("Diff is: {}", difficulty);
// 		assert_eq!(difficulty, Difficulty::from_num(21240));

// 		in_nonces[41] = 23402320128419283;
// 		in_nonces[11] = 81239481234781924;
// 		let proof = Proof::new(in_nonces.clone(), 31);
// 		let difficulty = proof.to_difficulty(120000, 32348);
// 		println!("Diff is: {}", difficulty);
// 		assert_eq!(difficulty, Difficulty::from_num(36591));

// 		for i in in_nonces.iter_mut() {
// 			*i = std::u64::MAX;
// 		}
// 		let proof = Proof::new(in_nonces.clone(), 35);
// 		let difficulty = proof.to_difficulty(1300000, 92348);
// 		println!("Diff is: {}", difficulty);
// 		assert_eq!(difficulty, Difficulty::from_num(296303));
// 	}
// }
