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

use account::{Address, Balance, NormalAddress};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, PublicKey as Pk, SecretKey as Sk, Signature};
use std::io::Cursor;
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ChangeMinter {
    /// The current minter
    pub minter: NormalAddress,

    /// The address of the new minter
    pub new_minter: Address,

    /// The global identifier of the mintable asset
    pub asset_hash: Hash,

    /// The global identifier of the asset in which
    /// the transaction fee is paid in.
    pub fee_hash: Hash,

    /// The transaction's fee
    pub fee: Balance,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl ChangeMinter {
    pub const TX_TYPE: u8 = 8;

    /// Signs the transaction with the given secret key.
    pub fn sign(&mut self, skey: &Sk) {
        // Assemble data
        let message = assemble_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey, &self.minter.pkey());
        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_message(&self);

        match self.signature {
            Some(ref sig) => crypto::verify(&message, sig, &self.minter.pkey()),
            None => false,
        }
    }

    /// Serializes the transaction struct to a binary format.
    ///
    /// Fields:
    /// 1) Transaction type(8)  - 8bits
    /// 2) Fee length           - 8bits
    /// 3) Minter               - 33byte binary
    /// 4) New Minter           - 33byte binary
    /// 5) Asset hash           - 32byte binary
    /// 6) Fee hash             - 32byte binary
    /// 7) Hash                 - 32byte binary
    /// 8) Signature            - 64byte binary
    /// 9) Fee                  - Binary of fee length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();

        let hash = if let Some(hash) = &self.hash {
            &hash.0
        } else {
            return Err("Hash field is missing");
        };

        let mut signature = if let Some(signature) = &self.signature {
            signature.to_bytes()
        } else {
            return Err("Signature field is missing");
        };

        let tx_type: u8 = Self::TX_TYPE;
        let minter = &self.minter.to_bytes();
        let new_minter = &self.new_minter.to_bytes();
        let asset_hash = &&self.asset_hash.0;
        let fee_hash = &&self.fee_hash.0;
        let fee = &self.fee.to_bytes();
        let fee_len = fee.len();

        // Write to buffer
        buf.write_u8(tx_type).unwrap();
        buf.write_u8(fee_len as u8).unwrap();

        buf.append(&mut minter.to_vec());
        buf.append(&mut new_minter.to_vec());
        buf.append(&mut asset_hash.to_vec());
        buf.append(&mut fee_hash.to_vec());
        buf.append(&mut hash.to_vec());
        buf.append(&mut signature);
        buf.append(&mut fee.to_vec());

        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ChangeMinter, &'static str> {
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

        let fee_len = if let Ok(result) = rdr.read_u8() {
            result
        } else {
            return Err("Bad fee len");
        };

        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..2).collect();

        let minter = if buf.len() > 33 as usize {
            let minter_vec: Vec<u8> = buf.drain(..33).collect();

            match NormalAddress::from_bytes(&minter_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let new_minter = if buf.len() > 33 as usize {
            let new_minter_vec: Vec<u8> = buf.drain(..33).collect();

            match Address::from_bytes(&new_minter_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let asset_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let fee_hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let hash = if buf.len() > 32 as usize {
            let mut hash = [0; 32];
            let hash_vec: Vec<u8> = buf.drain(..32).collect();

            hash.copy_from_slice(&hash_vec);

            Hash(hash)
        } else {
            return Err("Incorrect packet structure");
        };

        let signature = if buf.len() > 64 as usize {
            let sig_vec: Vec<u8> = buf.drain(..64).collect();

            match Signature::from_bytes(&sig_vec) {
                Ok(sig) => sig,
                Err(_) => return Err("Bad signature"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let fee = if buf.len() == fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_) => return Err("Bad gas price"),
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let change_minter = ChangeMinter {
            minter: minter,
            new_minter: new_minter,
            asset_hash: asset_hash,
            fee_hash: fee_hash,
            fee: fee,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(change_minter)
    }

    /// Returns a random valid transaction for the provided state.
    pub fn arbitrary_valid(trie: &mut TrieDBMut<BlakeDbHasher, Codec>, sk: Sk) -> Self {
        unimplemented!();
    }

    impl_hash!();
}

fn assemble_message(obj: &ChangeMinter) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut minter = obj.minter.to_bytes();
    let mut new_minter = obj.new_minter.to_bytes();
    let mut fee = obj.fee.to_bytes();
    let asset_hash = obj.asset_hash.0;
    let fee_hash = obj.fee_hash.0;

    // Compose data to hash
    buf.append(&mut minter);
    buf.append(&mut new_minter);
    buf.append(&mut asset_hash.to_vec());
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for ChangeMinter {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ChangeMinter {
        ChangeMinter {
            minter: Arbitrary::arbitrary(g),
            new_minter: Arbitrary::arbitrary(g),
            asset_hash: Arbitrary::arbitrary(g),
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
        fn serialize_deserialize(tx: ChangeMinter) -> bool {
            tx == ChangeMinter::from_bytes(&ChangeMinter::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: ChangeMinter) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_signature(
            new_minter: Address,
            fee: Balance,
            asset_hash: Hash,
            fee_hash: Hash
        ) -> bool {
            let id = Identity::new();

            let mut tx = ChangeMinter {
                minter: NormalAddress::from_pkey(*id.pkey()),
                new_minter: new_minter,
                fee: fee,
                asset_hash: asset_hash,
                fee_hash: fee_hash,
                signature: None,
                hash: None
            };

            tx.sign(id.skey());
            tx.verify_sig()
        }
    }
}
