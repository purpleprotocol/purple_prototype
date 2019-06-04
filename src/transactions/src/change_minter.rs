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

use account::{NormalAddress, Address, Balance};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Signature, Hash, PublicKey as Pk, SecretKey as Sk};

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
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, &skey);
        self.signature = Some(signature);
    }

    /// Verifies the signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_sig(&mut self) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => {
                crypto::verify(&message, sig, &self.minter.pkey())
            }
            None => false,
        }
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &ChangeMinter) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

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
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &ChangeMinter) -> Vec<u8> {
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
        // fn serialize_deserialize(tx: ChangeMinter) -> bool {
        //     tx == ChangeMinter::from_bytes(&ChangeMinter::to_bytes(&tx).unwrap()).unwrap()
        // }

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

            tx.sign(id.skey().clone());
            tx.verify_sig()
        }
    }
}
