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

#![feature(extern_prelude)]

#[macro_use]
extern crate quickcheck;

#[macro_use]
extern crate serde_derive;

extern crate account;
extern crate causality;
extern crate crypto;
extern crate network;
extern crate serde;
extern crate byteorder;
extern crate rand;

#[macro_use]
mod macros;

mod burn;
mod call;
mod create_currency;
mod create_mintable;
mod genesis;
mod open_contract;
mod receive;
mod send;
mod mint;
mod issue_shares;
mod open_multi_sig;
mod open_shares;
mod transaction;

pub use burn::*;
pub use call::*;
pub use create_currency::*;
pub use create_mintable::*;
pub use genesis::*;
pub use open_contract::*;
pub use receive::*;
pub use send::*;
pub use issue_shares::*;
pub use mint::*;
pub use open_multi_sig::*;
pub use open_shares::*;
pub use transaction::*;

use rand::Rng;
use quickcheck::Arbitrary;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Tx {
    Call(Call),
    OpenContract(OpenContract),
    Receive(Receive),
    Send(Send),
    Burn(Burn),
    CreateCurrency(CreateCurrency),
    CreateMintable(CreateMintable),
    Mint(Mint),
    IssueShares(IssueShares),
    OpenMultiSig(OpenMultiSig),
    OpenShares(OpenShares)
}

impl Tx {
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        match *self {
            Tx::Call(ref tx)            => tx.to_bytes(),
            Tx::OpenContract(ref tx)    => tx.to_bytes(),
            Tx::Receive(ref tx)         => tx.to_bytes(),
            Tx::Send(ref tx)            => tx.to_bytes(),
            Tx::Burn(ref tx)            => tx.to_bytes(),
            Tx::CreateCurrency(ref tx)  => tx.to_bytes(),
            Tx::CreateMintable(ref tx)  => tx.to_bytes(),
            Tx::Mint(ref tx)            => tx.to_bytes(),
            Tx::IssueShares(ref tx)     => tx.to_bytes(),
            Tx::OpenMultiSig(ref tx)    => tx.to_bytes(),
            Tx::OpenShares(ref tx)      => tx.to_bytes()
        }
    }
}

impl Arbitrary for Tx {
    fn arbitrary<G : quickcheck::Gen>(g: &mut G) -> Tx {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(1, 11);

        match random {
            1  => Tx::Call(Arbitrary::arbitrary(g)),
            2  => Tx::OpenContract(Arbitrary::arbitrary(g)),
            3  => Tx::Receive(Arbitrary::arbitrary(g)),
            4  => Tx::Send(Arbitrary::arbitrary(g)),
            5  => Tx::Burn(Arbitrary::arbitrary(g)),
            6  => Tx::CreateCurrency(Arbitrary::arbitrary(g)),
            7  => Tx::CreateMintable(Arbitrary::arbitrary(g)),
            8  => Tx::Mint(Arbitrary::arbitrary(g)),
            9  => Tx::IssueShares(Arbitrary::arbitrary(g)),
            10 => Tx::OpenMultiSig(Arbitrary::arbitrary(g)),
            11 => Tx::OpenShares(Arbitrary::arbitrary(g)),
            _  => panic!()
        }
    }
}