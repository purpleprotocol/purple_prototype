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
use std::str;
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OpenContract {
    owner: Address,
    code: Vec<u8>,
    default_state: Vec<u8>,
    fee: Balance,
    fee_hash: Hash,
    self_payable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

impl OpenContract {
    pub const TX_TYPE: u8 = 2;

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
                if let Address::Normal(_) = self.owner {
                    let result = Signature::Normal(signature);
                    self.signature = Some(result);
                } else {
                    panic!("Invalid address type");
                }
            },
            Some(Signature::MultiSig(ref mut sig)) => {
                if let Address::Normal(_) = self.owner {
                    panic!("Invalid address type");
                } else {
                    // Append signature to the multi sig struct
                    sig.append_sig(signature);
                }           
            },
            None => {
                if let Address::Normal(_) = self.owner {
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
                if let Address::Normal(ref addr) = self.owner {
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

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(2)      - 8bits
    /// 2) Self payable             - 8bits
    /// 3) Fee length               - 8bits
    /// 4) Signature length         - 16bits
    /// 5) State length             - 16bits
    /// 6) Code length              - 16bits
    /// 7) Owner                    - 33byte binary
    /// 8) Fee hash                 - 32byte binary
    /// 9) Hash                     - 32byte binary
    /// 10) Signature               - Binary of signature length
    /// 11) Fee                     - Binary of fee length
    /// 12) Default state           - Binary of state length
    /// 13) Code                    - Binary of code length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

        let hash = if let Some(hash) = &self.hash {
            &hash.0
        } else {
            return Err("Hash field is missing");
        };

        let signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let self_payable: u8 = if self.self_payable { 1 } else { 0 };
        let owner = &self.owner.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let code = &self.code;
        let default_state = &self.default_state;
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();
        let code_len = code.len();
        let signature_len = signature.len();
        let state_len = default_state.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(self_payable).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(state_len as u16).unwrap();
        buffer.write_u16::<BigEndian>(code_len as u16).unwrap();

        buffer.append(&mut owner.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut signature.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut default_state.to_vec());
        buffer.append(&mut code.to_vec());

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<OpenContract, &'static str> {
        let mut rdr = Cursor::new(bytes.to_vec());
        let tx_type = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad transaction type");
        };

        if tx_type != Self::TX_TYPE {
            return Err("Bad transation type");
        }

        rdr.set_position(1);

        let self_payable = if let Ok(result) = rdr.read_u8() {
            match result {
                0 => false,
                1 => true,
                _ => return Err("Invalid self payable field")
            }
        } else {
            return Err("Bad self payable field");
        };

        rdr.set_position(2);

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        rdr.set_position(3);

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
        };

        rdr.set_position(5);

        let state_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad state len");
        };

        rdr.set_position(7);

        let code_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad code len");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..9).collect();

        let owner = if buf.len() > 33 as usize {
            let owner_vec: Vec<u8> = buf.drain(..33).collect();
            
            match Address::from_bytes(&owner_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the owner field");
        };

        let fee_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the fee hash field");
        };

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the hash field");
        };

        let signature = if buf.len() > signature_len as usize {
            let sig_vec: Vec<u8> = buf.drain(..signature_len as usize).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig)   => sig,
                Err(err)  => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size of the signature field");
        };

        let fee = if buf.len() >= fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad fee")
            }
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the fee field")
        };

        let default_state = if buf.len() >= state_len as usize {
            buf.drain(..state_len as usize).collect()
        } else {
            return Err("Incorrect packet structure! Buffer size is smaller than the size for the default state field")
        };

        let code = if buf.len() == code_len as usize {
            buf.drain(..code_len as usize).collect()
        } else {
            return Err("Incorrect packet structure! Buffer size is not equal with the size for the code field")
        };

        let open_contract = OpenContract {
            owner: owner,
            fee_hash: fee_hash,
            fee: fee,
            default_state: default_state,
            self_payable: self_payable,
            code: code,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(open_contract)
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &OpenContract) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut owner = obj.owner.to_bytes();
    let self_payable: u8 = if obj.self_payable { 1 } else { 0 };
    let fee_hash = &obj.fee_hash.0;
    let code = &obj.code;
    let default_state = &obj.default_state;
    let mut fee = obj.fee.to_bytes();

    buf.write_u8(self_payable).unwrap();

    // Compose data to hash
    buf.append(&mut owner);
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut code.to_vec());
    buf.append(&mut default_state.to_vec());
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &OpenContract) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut owner = obj.owner.to_bytes();
    let self_payable: u8 = if obj.self_payable { 1 } else { 0 };
    let fee_hash = &obj.fee_hash.0;
    let code = &obj.code;
    let default_state = &obj.default_state;
    let mut fee = obj.fee.to_bytes();

    buf.write_u8(self_payable).unwrap();

    // Compose data to hash
    buf.append(&mut owner);
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut code.to_vec());
    buf.append(&mut default_state.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for OpenContract {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> OpenContract {
        OpenContract {
            owner: Arbitrary::arbitrary(g),
            code: Arbitrary::arbitrary(g),
            default_state: Arbitrary::arbitrary(g),
            self_payable: Arbitrary::arbitrary(g),
            fee: Arbitrary::arbitrary(g),
            fee_hash: Arbitrary::arbitrary(g),
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
        fn serialize_deserialize(tx: OpenContract) -> bool {
            tx == OpenContract::from_bytes(&OpenContract::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: OpenContract) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            code: Vec<u8>,
            default_state: Vec<u8>,
            fee: Balance,
            fee_hash: Hash,
            self_payable: bool
        ) -> bool {
            let id = Identity::new();

            let mut tx = OpenContract {
                owner: Address::normal_from_pkey(*id.pkey()),
                fee_hash: fee_hash,
                fee: fee,
                self_payable: self_payable,
                default_state: default_state,
                code: code,
                signature: None,
                hash: None
            };

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }

        fn verify_multi_signature(
            code: Vec<u8>,
            default_state: Vec<u8>,
            self_payable: bool,
            fee: Balance,
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

            let mut tx = OpenContract {
                owner: Address::multi_sig_from_pkeys(&pkeys, *creator_id.pkey(), 4314),
                fee_hash: fee_hash,
                self_payable: self_payable,
                fee: fee,
                default_state: default_state,
                code: code,
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
            code: Vec<u8>,
            default_state: Vec<u8>,
            fee: Balance,
            fee_hash: Hash,
            self_payable: bool
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

            let mut tx = OpenContract {
                owner: Address::shareholders_from_pkeys(&pkeys, *creator_id.pkey(), 4314),
                fee_hash: fee_hash,
                fee: fee,
                default_state: default_state,
                code: code,
                self_payable: self_payable,
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