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

pub mod normal;
pub mod multi_sig;
pub mod shareholders;

use crypto::PublicKey;
use addresses::normal::*;
use addresses::multi_sig::*;
use addresses::shareholders::*;

#[derive(Hash, PartialEq, Eq, Serialize, Deserialize, Clone, Debug)]
pub enum Address {
    Normal(NormalAddress),
    MultiSig(MultiSigAddress),
    Shareholders(ShareholdersAddress)
}

impl Address {
    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Address::Normal(ref addr)        => addr.to_bytes(),
            Address::MultiSig(ref addr)      => addr.to_bytes(),
            Address::Shareholders(ref addr)  => addr.to_bytes()
        }
    }

    pub fn multi_sig_from_pkeys(pkeys: &[PublicKey], creator_address: PublicKey, nonce: u64) -> Address {
        let addresses: Vec<NormalAddress> = pkeys
            .iter()
            .map(|pk| NormalAddress::from_pkey(*pk))
            .collect();
        
        Address::MultiSig(MultiSigAddress::compute(&addresses, NormalAddress::from_pkey(creator_address), nonce))
    }

    pub fn shareholders_from_pkeys(pkeys: &[PublicKey], creator_address: PublicKey, nonce: u64) -> Address {
        let addresses: Vec<NormalAddress> = pkeys
            .iter()
            .map(|pk| NormalAddress::from_pkey(*pk))
            .collect();
        
        Address::Shareholders(ShareholdersAddress::compute(&addresses, NormalAddress::from_pkey(creator_address), nonce))
    }

    pub fn normal_from_pkey(pkey: PublicKey) -> Address {
        Address::Normal(NormalAddress::from_pkey(pkey))
    }

    pub fn from_bytes(bin: &[u8]) -> Result<Address, &'static str> {
        let addr_type = bin[0];

        match addr_type {
            1 => {
                match NormalAddress::from_bytes(bin) {
                    Ok(result) => Ok(Address::Normal(result)),
                    Err(err)   => Err(err)
                }
            },
            2 => {
                match MultiSigAddress::from_bytes(bin) {
                    Ok(result) => Ok(Address::MultiSig(result)),
                    Err(err)   => Err(err)
                }
            },
            3 => {
                match ShareholdersAddress::from_bytes(bin) {
                    Ok(result) => Ok(Address::Shareholders(result)),
                    Err(err)   => Err(err)
                }
            },
            _ => {
                Err("Bad address type!")
            }
        }
    }
}

use quickcheck::Arbitrary;
use rand::Rng;

impl Arbitrary for Address {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Address {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(1, 3);

        match random {
            1  => Address::Normal(Arbitrary::arbitrary(g)),
            2  => Address::MultiSig(Arbitrary::arbitrary(g)),
            3  => Address::Shareholders(Arbitrary::arbitrary(g)),
            _  => panic!()
        }
    }
}