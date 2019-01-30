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

use account::{Address, Balance, Signature, ShareMap, MultiSig};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, SecretKey as Sk, PublicKey as Pk};

pub const ASSET_NAME_SIZE: usize = 32;
pub const META_FIELD_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateUnique {
    /// The asset creator's address
    pub creator: Address,

    /// The receiver of the asset
    pub receiver: Address,

    /// The global identifier of the asset
    pub asset_hash: Hash,

    /// The id of the currency that the transaction is paid in
    pub fee_hash: Hash,

    /// The name of the asset
    pub name: [u8; ASSET_NAME_SIZE],

    // 5 optional fields of 32 bytes for metadata. 160 bytes in total.
    pub meta1: Option<[u8; META_FIELD_SIZE]>,
    pub meta2: Option<[u8; META_FIELD_SIZE]>,
    pub meta3: Option<[u8; META_FIELD_SIZE]>,
    pub meta4: Option<[u8; META_FIELD_SIZE]>,
    pub meta5: Option<[u8; META_FIELD_SIZE]>,

    /// The fee of the transaction
    pub fee: Balance,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl CreateUnique {
    pub const TX_TYPE: u8 = 12;

    /// Signs the transaction with the given secret key.
    ///
    /// This function will panic if there already exists
    /// a signature and the address type doesn't match
    /// the signature type.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        match self.signature {
            Some(Signature::Normal(_)) => { 
                if let Address::Normal(_) = self.creator {
                    let result = Signature::Normal(signature);
                    self.signature = Some(result);
                } else {
                    panic!("Invalid address type");
                }
            },
            Some(Signature::MultiSig(ref mut sig)) => {
                if let Address::Normal(_) = self.creator {
                    panic!("Invalid address type");
                } else {
                    // Append signature to the multi sig struct
                    sig.append_sig(signature);
                }           
            },
            None => {
                if let Address::Normal(_) = self.creator {
                    // Create a normal signature
                    let result = Signature::Normal(signature);
                    
                    // Attach signature to struct
                    self.signature = Some(result);
                } else {
                    // Create a multi signature
                    let result = Signature::MultiSig(MultiSig::from_sig(signature));

                    // Attach signature to struct
                    self.signature = Some(result);
                }
            }
        };
    }
    
    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    ///
    /// This function panics if the transaction has a multi 
    /// signature attached to it or if the signer's address
    /// is not a normal address.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(Signature::Normal(ref sig)) => { 
                if let Address::Normal(ref addr) = self.creator {
                    crypto::verify(&message, sig.clone(), addr.pkey())
                } else {
                    panic!("The address of the signer is not a normal address!");
                }
            },
            Some(Signature::MultiSig(_)) => {
                panic!("Calling this function on a multi signature transaction is not permitted!");
            },
            None => {
                false
            }
        }
    }

    /// Verifies the multi signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    ///
    /// This function panics if the transaction has a multi 
    /// signature attached to it or if the signer's address
    /// is not a normal address.
    pub fn verify_multi_sig(&mut self, required_keys: u8, pkeys: &[Pk]) -> bool {
        if pkeys.len() < required_keys as usize {
            false
        } else {
            let message = assemble_sign_message(&self);

            match self.signature {
                Some(Signature::Normal(_)) => { 
                    panic!("Calling this function on a transaction with a normal signature is not permitted!");
                },
                Some(Signature::MultiSig(ref sig)) => {
                    sig.verify(&message, required_keys, pkeys)
                },
                None => {
                    false
                }
            }
        }
    }

    /// Verifies the multi signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_multi_sig_shares(&mut self, required_percentile: u8, share_map: ShareMap) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(Signature::Normal(_)) => { 
                panic!("Calling this function on a transaction with a normal signature is not permitted!");
            },
            Some(Signature::MultiSig(ref sig)) => {
                sig.verify_shares(&message, required_percentile, share_map)
            },
            None => {
                false
            }
        }
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &CreateUnique) -> Vec<u8> {
    unimplemented!();
}

fn assemble_sign_message(obj: &CreateUnique) -> Vec<u8> {
    unimplemented!();
}
