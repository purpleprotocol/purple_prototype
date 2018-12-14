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

use account::{ShareholdersAddress, Address, Balance, MultiSig, ShareMap};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{Hash, SecretKey as Sk};
use std::io::Cursor;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IssueShares {
    issuer: ShareholdersAddress,
    receiver: Address,
    shares: u64,
    fee_hash: Hash,
    fee: Balance,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<MultiSig>,
}

impl IssueShares {
    pub const TX_TYPE: u8 = 7;

    /// Signs the transaction with the given secret key.
    pub fn sign(&mut self, skey: Sk) {
        // Assemble data
        let message = assemble_sign_message(&self);

        // Sign data
        let signature = crypto::sign(&message, skey);

        match self.signature {
            Some(ref mut sig) => {
                // Append signature to the multi sig struct
                sig.append_sig(signature);        
            },
            None => {
                // Create a multi signature
                let result = MultiSig::from_sig(signature);

                // Attach signature to struct
                self.signature = Some(result);
            }
        };
    }

    /// Verifies the multi signature of the transaction.
    ///
    /// Returns `false` if the signature field is missing.
    pub fn verify_multi_sig_shares(&mut self, required_percentile: u8, share_map: ShareMap) -> bool {
        let message = assemble_sign_message(&self);

        match self.signature {
            Some(ref sig) => {
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
    /// 1) Transaction type(7)      - 8bits
    /// 2) Fee length               - 8bits
    /// 3) Signature length         - 16bits
    /// 4) Amount of issued shares  - 64bits
    /// 5) Issuer                   - 33byte binary
    /// 6) Receiver                 - 33byte binary
    /// 7) Fee hash                 - 32byte binary
    /// 8) Hash                     - 32byte binary
    /// 9) Fee                      - Binary of fee length
    /// 10) Signature               - Binary of signature length
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer: Vec<u8> = Vec::new();
        let tx_type: u8 = Self::TX_TYPE;

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

        let issuer = &self.issuer.to_bytes();
        let receiver = &self.receiver.to_bytes();
        let fee_hash = &&self.fee_hash.0;
        let shares = &self.shares;
        let fee = &self.fee.to_bytes();

        let fee_len = fee.len();
        let signature_len = signature.len();

        buffer.write_u8(tx_type).unwrap();
        buffer.write_u8(fee_len as u8).unwrap();
        buffer.write_u16::<BigEndian>(signature_len as u16).unwrap();
        buffer.write_u64::<BigEndian>(*shares).unwrap();

        buffer.append(&mut issuer.to_vec());
        buffer.append(&mut receiver.to_vec());
        buffer.append(&mut fee_hash.to_vec());
        buffer.append(&mut hash.to_vec());
        buffer.append(&mut fee.to_vec());
        buffer.append(&mut signature);

        Ok(buffer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<IssueShares, &'static str> {
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

        rdr.set_position(2);

        let signature_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
            result
        } else {
            return Err("Bad signature len");
        };

        rdr.set_position(4);

        let shares = if let Ok(result) = rdr.read_u64::<BigEndian>() {
            result
        } else {
            return Err("Bad shares");
        };

        // Consume cursor
        let mut buf: Vec<u8> = rdr.into_inner();
        let _: Vec<u8> = buf.drain(..12).collect();

        let issuer = if buf.len() > 33 as usize {
            let issuer_vec: Vec<u8> = buf.drain(..33).collect();
            
            match ShareholdersAddress::from_bytes(&issuer_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let receiver = if buf.len() > 33 as usize {
            let receiver_vec: Vec<u8> = buf.drain(..33).collect();
            
            match Address::from_bytes(&receiver_vec) {
                Ok(addr) => addr,
                Err(err) => return Err(err)
            }
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

        let fee = if buf.len() > fee_len as usize {
            let fee_vec: Vec<u8> = buf.drain(..fee_len as usize).collect();

            match Balance::from_bytes(&fee_vec) {
                Ok(result) => result,
                Err(_)     => return Err("Bad fee")
            }
        } else {
            return Err("Incorrect packet structure")
        };

        let signature = if buf.len() == signature_len as usize {
            let sig_vec: Vec<u8> = buf.drain(..signature_len as usize).collect();

            match MultiSig::from_bytes(&sig_vec) {
                Ok(sig)   => sig,
                Err(err)  => return Err(err)
            }
        } else {
            return Err("Incorrect packet structure");
        };

        let issue_shares = IssueShares {
            issuer: issuer,
            receiver: receiver,
            shares: shares,
            fee_hash: fee_hash,
            fee: fee,
            hash: Some(hash),
            signature: Some(signature),
        };

        Ok(issue_shares)
    }

    impl_hash!();
}

fn assemble_hash_message(obj: &IssueShares) -> Vec<u8> {
    let mut signature = if let Some(ref sig) = obj.signature {
        sig.to_bytes()
    } else {
        panic!("Signature field is missing!");
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut issuer = obj.issuer.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let shares = obj.shares;
    let mut fee = obj.fee.to_bytes();

    buf.write_u64::<BigEndian>(shares).unwrap();

    // Compose data to hash
    buf.append(&mut issuer);
    buf.append(&mut receiver);
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);
    buf.append(&mut signature);

    buf
}

fn assemble_sign_message(obj: &IssueShares) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut issuer = obj.issuer.to_bytes();
    let mut receiver = obj.receiver.to_bytes();
    let fee_hash = &obj.fee_hash.0;
    let shares = obj.shares;
    let mut fee = obj.fee.to_bytes();

    buf.write_u64::<BigEndian>(shares).unwrap();

    // Compose data to sign
    buf.append(&mut issuer);
    buf.append(&mut receiver);
    buf.append(&mut fee_hash.to_vec());
    buf.append(&mut fee);

    buf
}

use quickcheck::Arbitrary;

impl Arbitrary for IssueShares {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> IssueShares {
        IssueShares {
            issuer: Arbitrary::arbitrary(g),
            receiver: Arbitrary::arbitrary(g),
            shares: Arbitrary::arbitrary(g),
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
    use crypto::{Identity, PublicKey as Pk};

    quickcheck! {
        fn serialize_deserialize(tx: IssueShares) -> bool {
            tx == IssueShares::from_bytes(&IssueShares::to_bytes(&tx).unwrap()).unwrap()
        }

        fn verify_hash(tx: IssueShares) -> bool {
            let mut tx = tx;

            for _ in 0..3 {
                tx.hash();
            }

            tx.verify_hash()
        }

        fn verify_multi_signature_shares(
            receiver: Address, 
            fee: Balance, 
            shares: u64,
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

            let mut tx = IssueShares {
                issuer: ShareholdersAddress::compute(&addresses, NormalAddress::from_pkey(*creator_id.pkey()), 4314),
                receiver: receiver,
                shares: shares,
                fee: fee,
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