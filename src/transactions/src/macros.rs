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
*/

macro_rules! impl_hash {
    () => {
        /// Computes the transaction's hash.
        ///
        /// This function will panic if the signature field is missing.
        pub fn hash(&mut self) {
            // Assemble data
            let message = assemble_hash_message(&self);

            // Hash data
            let hash = crypto::hash_slice(&message);

            self.hash = Some(hash);
        }

        /// Computes the message that is passed to the 
        /// hash function of this transaction.
        ///
        /// This function will panic if the signature field is missing.
        pub fn compute_hash_message(&self) -> Vec<u8> { assemble_hash_message(&self) }

        /// Verifies the correctness of the hash of the transaction.
        ///
        /// This function will panic if the hash field or if the 
        /// signature field is missing.
        pub fn verify_hash(&mut self) -> bool {
            let hash = if let Some(hash) = &self.hash {
                hash.0
            } else {
                panic!("Hash field is missing!");
            };
            
            let oracle_message = assemble_hash_message(&self);
            let oracle_hash = crypto::hash_slice(&oracle_message);

            hash == oracle_hash.0
        }
    }
}

macro_rules! impl_validate_signature {
    () => {
        fn validate_signature(&mut self, creator: &Address, signature: &Option<Signature>, trie: &TrieDBMut<BlakeDbHasher, Codec>) -> bool {
            use crypto::PublicKey as Pk;
            use account::{NormalAddress, Shares};
            
            match (creator, signature) {
                (&Address::Normal(_), &Some(Signature::Normal(_))) => {
                    if !self.verify_sig() {
                        return false;
                    }
                },
                (&Address::MultiSig(_), &Some(Signature::MultiSig(_))) => {
                    let creator = creator.to_bytes();
                    let creator = hex::encode(creator);

                    let required_keys_key = format!("{}.r", creator);
                    let required_keys_key = required_keys_key.as_bytes();
                    let keys_key = format!("{}.k", creator);
                    let keys_key = keys_key.as_bytes();

                    let required_keys = match trie.get(&required_keys_key) {
                        Ok(Some(required_keys)) => decode_u8!(required_keys).unwrap(),
                        Ok(None)                => return false,
                        Err(err)                => panic!(err)
                    };

                    let keys: Result<Vec<Pk>, &'static str> = match trie.get(&keys_key) {
                        Ok(Some(keys)) => {
                            let keys: Vec<Vec<u8>> = rlp::decode_list(&keys);
                            
                            keys
                                .iter()
                                .map(|k| NormalAddress::from_bytes(k))
                                .map(|r| match r {
                                    Ok(r)    => Ok(r.pkey()),
                                    Err(err) => Err(err)
                                })
                                .collect()
                        },
                        Ok(None) => return false,
                        Err(err) => panic!(err)
                    }; 

                    let keys = if let Ok(keys) = keys {
                        keys
                    } else {
                        return false;
                    };

                    if !self.verify_multi_sig(required_keys, &keys) {
                        return false;
                    }
                },
                (&Address::Shareholders(_), &Some(Signature::MultiSig(_))) => {
                    let creator = creator.to_bytes();
                    let creator = hex::encode(creator);

                    let shares_key = format!("{}.s", creator);
                    let share_map_key = format!("{}.sm", creator);
                    let shares_key = shares_key.as_bytes();
                    let share_map_key = share_map_key.as_bytes();

                    let shares = match trie.get(&shares_key) {
                        Ok(Some(result)) => Shares::from_bytes(&result).unwrap(),
                        Ok(None)         => return false,
                        Err(err)         => panic!(err)
                    };

                    let share_map = match trie.get(&share_map_key) {
                        Ok(Some(result)) => ShareMap::from_bytes(&result).unwrap(),
                        Ok(None)         => return false,
                        Err(err)         => panic!(err)
                    };

                    if !self.verify_multi_sig_shares(shares.required_percentile, share_map) {
                        return false;
                    }
                },
                _ => return false
            };

            true
        }
    }
}