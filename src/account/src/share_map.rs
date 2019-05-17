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

use addresses::normal::NormalAddress;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::Signature;
use hashbrown::HashMap;
use quickcheck::Arbitrary;
use rust_decimal::Decimal;
use std::io::Cursor;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareMap {
    share_map: HashMap<NormalAddress, u32>,
    pub issued_shares: u32,
}

impl ShareMap {
    pub fn new() -> ShareMap {
        ShareMap {
            share_map: HashMap::new(),
            issued_shares: 0,
        }
    }

    pub fn keys(&self) -> Vec<NormalAddress> {
        let mut buf: Vec<NormalAddress> = vec![];

        for (k, _) in self.share_map.iter() {
            buf.push(k.clone());
        }

        buf
    }

    pub fn get(&self, key: NormalAddress) -> Option<u32> {
        match self.share_map.get(&key) {
            Some(res) => Some(res.clone()),
            None => None,
        }
    }

    /// Lists a new shareholder with the given amount of shares
    pub fn add_shareholder(&mut self, addr: NormalAddress, shares: u32) {
        self.share_map.insert(addr, shares);
        self.issued_shares += shares;
    }

    /// Adds the given amount of shares to the shareholder with the
    /// given address, raising the total amount of issued shares.
    pub fn issue_shares(&mut self, addr: NormalAddress, shares: u32) {
        let shares = match self.share_map.get(&addr) {
            Some(current_shares) => current_shares + shares,
            None => shares,
        };

        self.share_map.insert(addr, shares);
        self.issued_shares += shares;
    }

    /// Transfers a given amount of shares from a shareholder.
    ///
    /// The receiving address will be listed in the share map if
    /// it isn't so already.
    ///
    /// This function will panic if the `from` address isn't listed
    /// in the share map or the given amount is greater than the
    /// owned shares of the `from` address.
    pub fn transfer_shares(&mut self, from: &NormalAddress, to: &NormalAddress, amount: u32) {
        let from_shares = match self.share_map.get(from) {
            Some(current_shares) => {
                if current_shares < &amount {
                    panic!("Given amount is greater than owned shares!");
                }

                current_shares - &amount
            }
            None => {
                panic!("From address isn't listed!");
            }
        };

        let to_shares = match self.share_map.get(to) {
            Some(current_shares) => current_shares + &amount,
            None => amount,
        };

        // Remove entry from share map if all shares are transferred
        if from_shares == 0 {
            self.share_map.remove(from);
        } else {
            self.share_map.insert(*from, from_shares);
        }

        self.share_map.insert(*to, to_shares);
    }

    /// Given a message and a signature, attempts to find a
    /// shareholder whose public key has successfuly verifies
    /// the signature.
    ///
    /// If a match is found, this function will return the owned
    /// ratio of shares of the signer.
    ///
    /// Returns `None` if no match is found.
    pub fn find_signer(&self, message: &[u8], signature: Signature) -> Option<Decimal> {
        let mut result: Option<Decimal> = None;

        // Attempt to find a matching key
        for (addr, shares) in self.share_map.iter() {
            if crypto::verify(message, signature.clone(), addr.pkey()) {
                // A match has been found
                let signer_ratio = (Decimal::from_str(&format!("{}.0", *shares)).unwrap()
                    / Decimal::from_str(&format!("{}.0", self.issued_shares)).unwrap())
                    * Decimal::from_str("100.0").unwrap();

                result = Some(signer_ratio);
                break;
            }
        }

        result
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<Vec<u8>> = Vec::with_capacity(self.share_map.len());

        for (k, v) in self.share_map.iter() {
            let mut b: Vec<u8> = Vec::with_capacity(36);
            let mut k = k.to_bytes();

            // Fields:
            // 1) Shares       - 32bits
            // 2) Shareholder  - 33byte binary
            b.write_u32::<BigEndian>(*v).unwrap();
            b.append(&mut k);

            buf.push(b);
        }

        rlp::encode_list::<Vec<u8>, _>(&buf)
    }

    pub fn from_bytes(bin: &[u8]) -> Result<ShareMap, &'static str> {
        let mut buf: HashMap<NormalAddress, u32> = HashMap::new();
        let decoded: Vec<Vec<u8>> = rlp::decode_list(bin);
        let mut issued_shares: u32 = 0;

        for bytes in decoded {
            if bytes.len() == 37 {
                let mut rdr = Cursor::new(bytes);
                let shares = if let Ok(result) = rdr.read_u32::<BigEndian>() {
                    result
                } else {
                    return Err("Bad shares");
                };

                let mut b = rdr.into_inner();
                let _: Vec<u8> = b.drain(..4).collect();

                let address_vec: Vec<u8> = b.drain(..33).collect();

                match NormalAddress::from_bytes(&address_vec) {
                    Ok(address) => {
                        issued_shares += shares;
                        buf.insert(address, shares)
                    }
                    Err(err) => return Err(err),
                };
            } else {
                return Err("Bad address");
            }
        }

        let share_map = ShareMap {
            share_map: buf,
            issued_shares: issued_shares,
        };

        Ok(share_map)
    }
}

impl IntoIterator for ShareMap {
    type Item = (NormalAddress, u32);
    type IntoIter = ::hashbrown::hash_map::IntoIter<NormalAddress, u32>;

    fn into_iter(self) -> Self::IntoIter {
        self.share_map.into_iter()
    }
}

impl Arbitrary for ShareMap {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> ShareMap {
        let sm: HashMap<NormalAddress, u32> = Arbitrary::arbitrary(g);
        let mut shares: u32 = 0;

        for (_, v) in sm.iter() {
            shares += v;
        }

        ShareMap {
            share_map: sm,
            issued_shares: shares,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;

    #[test]
    fn find_signer() {
        let mut sm = ShareMap::new();
        let id1 = Identity::new();
        let id2 = Identity::new();
        let id3 = Identity::new();

        let addr1 = NormalAddress::from_pkey(*id1.pkey());
        let addr2 = NormalAddress::from_pkey(*id2.pkey());
        let addr3 = NormalAddress::from_pkey(*id3.pkey());

        let message = b"test message";

        let sh1_signature = crypto::sign(message, id1.skey());
        let sh2_signature = crypto::sign(message, id2.skey());
        let sh3_signature = crypto::sign(message, id3.skey());

        let sh1_oracle = Decimal::from_str("30.0").unwrap();
        let sh2_oracle = Decimal::from_str("30.0").unwrap();
        let sh3_oracle = Decimal::from_str("40.0").unwrap();

        sm.add_shareholder(addr1, 15000);
        sm.add_shareholder(addr2, 15000);
        sm.add_shareholder(addr3, 20000);

        let result = sm.find_signer(message, sh1_signature).unwrap();

        assert_eq!(result, sh1_oracle);
        assert_eq!(sm.find_signer(message, sh2_signature).unwrap(), sh2_oracle);
        assert_eq!(sm.find_signer(message, sh3_signature).unwrap(), sh3_oracle);
    }

    quickcheck! {
        fn add_shareholder(sm: ShareMap, shareholder: NormalAddress, shares: u32) -> bool {
            let mut sm = sm.clone();

            sm.add_shareholder(shareholder, shares);
            sm.get(shareholder).unwrap() == shares
        }

        fn issue_shares_to_existing(shares: u32) -> bool {
            let mut sm = ShareMap::new();
            let id = Identity::new();
            let addr = NormalAddress::from_pkey(*id.pkey());

            sm.add_shareholder(addr, 1000);

            let keys = sm.keys();
            let (h, _) = keys.split_at(1);
            let k = h.to_vec().pop().unwrap();
            let current = sm.get(k).unwrap();

            sm.issue_shares(k, shares);
            sm.get(k).unwrap() == current + shares
        }

        fn issue_shares_to_new(sm: ShareMap, shareholder: NormalAddress, shares: u32) -> bool {
            let mut sm = sm.clone();

            sm.issue_shares(shareholder.clone(), shares);
            sm.get(shareholder).unwrap() == shares
        }

        fn transfer_shares() -> bool {
            let mut sm = ShareMap::new();
            let id1 = Identity::new();
            let id2 = Identity::new();
            let id3 = Identity::new();

            let addr1 = NormalAddress::from_pkey(*id1.pkey());
            let addr2 = NormalAddress::from_pkey(*id2.pkey());
            let addr3 = NormalAddress::from_pkey(*id3.pkey());

            sm.add_shareholder(addr1, 15000);
            sm.add_shareholder(addr2, 15000);
            sm.add_shareholder(addr3, 20000);

            let keys = sm.keys();
            let (h, t) = keys.split_at(1);
            let (h1, _) = t.split_at(1);

            let k1 = h.to_vec().pop().unwrap();
            let k2 = h1.to_vec().pop().unwrap();

            let sh1_current = sm.get(k1.clone()).unwrap();
            let sh2_current = sm.get(k2.clone()).unwrap();

            sm.transfer_shares(&k1, &k2, sh1_current - 1);

            sm.get(k1).unwrap() == 1 && sm.get(k2).unwrap() == sh2_current + sh1_current - 1
        }

        fn serialize_deserialize(sm: ShareMap) -> bool {
            sm == ShareMap::from_bytes(&ShareMap::to_bytes(&sm)).unwrap()
        }
    }
}
