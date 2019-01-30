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
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let mut name = obj.name;
    let mut fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to hash
    buf.append(&mut creator);
    buf.append(&mut receiver);
    buf.append(&mut name.to_vec());

    // Write meta if present
    if let Some(meta) = obj.meta1 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta2 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta3 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta4 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta5 {
        buf.append(&mut meta.to_vec());
    }

    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &CreateUnique) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut creator = obj.creator.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let mut name = obj.name;
    let mut fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to hash
    buf.append(&mut creator);
    buf.append(&mut receiver);
    buf.append(&mut name.to_vec());

    // Write meta if present
    if let Some(meta) = obj.meta1 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta2 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta3 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta4 {
        buf.append(&mut meta.to_vec());
    }

    if let Some(meta) = obj.meta5 {
        buf.append(&mut meta.to_vec());
    }

    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;
use rand::Rng;

#[derive(Clone, Debug)]
struct Array32(pub [u8; 32]);

impl Arbitrary for Array32 {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Array32 {
        Array32(rand::thread_rng().gen::<[u8; 32]>())
    }
}

impl Arbitrary for CreateUnique {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> CreateUnique {
        let name: Array32 = Arbitrary::arbitrary(g);
        let meta1: Option<Array32> = Arbitrary::arbitrary(g);
        let meta2: Option<Array32> = Arbitrary::arbitrary(g);
        let meta3: Option<Array32> = Arbitrary::arbitrary(g);
        let meta4: Option<Array32> = Arbitrary::arbitrary(g);
        let meta5: Option<Array32> = Arbitrary::arbitrary(g);

        let meta1 = if let Some(Array32(result)) = meta1 {
            Some(result)
        } else {
            None
        };

        let meta2 = if let Some(Array32(result)) = meta2 {
            Some(result)
        } else {
            None
        };

        let meta3 = if let Some(Array32(result)) = meta3 {
            Some(result)
        } else {
            None
        };

        let meta4 = if let Some(Array32(result)) = meta4 {
            Some(result)
        } else {
            None
        };

        let meta5 = if let Some(Array32(result)) = meta5 {
            Some(result)
        } else {
            None
        };

        CreateUnique {
            creator: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
            name: name.0,
            meta1: meta1,
            meta2: meta2,
            meta3: meta3,
            meta4: meta4,
            meta5: meta5,
            fee_hash: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            hash: Some(Arbitrary::arbitrary(g)),
            signature: Some(Arbitrary::arbitrary(g)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use account::NormalAddress;
    use crypto::Identity;

    quickcheck! {
        // fn serialize_deserialize(tx: CreateUnique) -> bool {
        //     tx == CreateUnique::from_bytes(&CreateUnique::to_bytes(&tx).unwrap()).unwrap()
        // }

        fn verify_hash(tx: CreateUnique) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            receiver: Address,
            fee: Balance, 
            name: Array32,
            meta: (Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>),
            asset_hash: Hash, 
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();
            let (
                meta1,
                meta2,
                meta3,
                meta4,
                meta5
            ) = meta;

            let meta1 = if let Some(Array32(result)) = meta1 {
                Some(result)
            } else {
                None
            };

            let meta2 = if let Some(Array32(result)) = meta2 {
                Some(result)
            } else {
                None
            };

            let meta3 = if let Some(Array32(result)) = meta3 {
                Some(result)
            } else {
                None
            };

            let meta4 = if let Some(Array32(result)) = meta4 {
                Some(result)
            } else {
                None
            };

            let meta5 = if let Some(Array32(result)) = meta5 {
                Some(result)
            } else {
                None
            };

            let mut tx = CreateUnique {
                creator: Address::normal_from_pkey(*id.pkey()),
                receiver: receiver,
                name: name.0,
                meta1: meta1,
                meta2: meta2,
                meta3: meta3,
                meta4: meta4,
                meta5: meta5,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }

        fn verify_multi_signature(
            receiver: Address,
            name: Array32,
            meta: (Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>),
            fee: Balance,
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let mut ids: Vec<Identity> = (0..30)
                .into_iter()
                .map(|_| Identity::new())
                .collect();

            let creator_id = ids.pop().unwrap();
            let pkeys: Vec<Pk> = ids
                .iter()
                .map(|i| *i.pkey())
                .collect();
            
            let (
                meta1,
                meta2,
                meta3,
                meta4,
                meta5
            ) = meta;

            let meta1 = if let Some(Array32(result)) = meta1 {
                Some(result)
            } else {
                None
            };

            let meta2 = if let Some(Array32(result)) = meta2 {
                Some(result)
            } else {
                None
            };

            let meta3 = if let Some(Array32(result)) = meta3 {
                Some(result)
            } else {
                None
            };

            let meta4 = if let Some(Array32(result)) = meta4 {
                Some(result)
            } else {
                None
            };

            let meta5 = if let Some(Array32(result)) = meta5 {
                Some(result)
            } else {
                None
            };

            let mut tx = CreateUnique {
                creator: Address::multi_sig_from_pkeys(&pkeys, *creator_id.pkey(), 4314),
                receiver: receiver,
                name: name.0,
                meta1: meta1,
                meta2: meta2,
                meta3: meta3,
                meta4: meta4,
                meta5: meta5,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            // Sign using each identity
            for id in ids {
                tx.sign(id.skey().clone());
            }
            
            tx.verify_multi_sig(10, &pkeys)
        }

        fn verify_multi_signature_shares(
            receiver: Address,
            name: Array32,
            meta: (Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>, Option<Array32>),
            fee: Balance,
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let mut ids: Vec<Identity> = (0..30)
                .into_iter()
                .map(|_| Identity::new())
                .collect();

            let creator_id = ids.pop().unwrap();
            let pkeys: Vec<Pk> = ids
                .iter()
                .map(|i| *i.pkey())
                .collect();

            let addresses: Vec<NormalAddress> = pkeys
                .iter()
                .map(|pk| NormalAddress::from_pkey(*pk))
                .collect();
            
            let mut share_map = ShareMap::new(); 

            for addr in addresses.clone() {
                share_map.add_shareholder(addr, 100);
            }

            let (
                meta1,
                meta2,
                meta3,
                meta4,
                meta5
            ) = meta;

            let meta1 = if let Some(Array32(result)) = meta1 {
                Some(result)
            } else {
                None
            };

            let meta2 = if let Some(Array32(result)) = meta2 {
                Some(result)
            } else {
                None
            };

            let meta3 = if let Some(Array32(result)) = meta3 {
                Some(result)
            } else {
                None
            };

            let meta4 = if let Some(Array32(result)) = meta4 {
                Some(result)
            } else {
                None
            };

            let meta5 = if let Some(Array32(result)) = meta5 {
                Some(result)
            } else {
                None
            };

            let mut tx = CreateUnique {
                creator: Address::shareholders_from_pkeys(&pkeys, *creator_id.pkey(), 4314),
                receiver: receiver,
                name: name.0,
                meta1: meta1,
                meta2: meta2,
                meta3: meta3,
                meta4: meta4,
                meta5: meta5,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            // Sign using each identity
            for id in ids {
                tx.sign(id.skey().clone());
            }
            
            tx.verify_multi_sig_shares(10, share_map)
        }
    }
}