/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::error::NetworkErr;
use crate::packets::*;
use crate::protocol_flow::transaction_propagation::sender_state::TxSenderState;
use crate::protocol_flow::transaction_propagation::outbound::OutboundPacket;
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::validation::sender::Sender;
use crypto::ShortHash;
use transactions::Tx;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TxSender {
    state: TxSenderState,
}

impl Sender<OutboundPacket, InboundPacket, Option<Arc<Tx>>> for TxSender {
    fn send(&mut self, data: Option<Arc<Tx>>) -> Result<OutboundPacket, NetworkErr> {
        match (&self.state, data) {
            (TxSenderState::Ready, Some(tx)) => {
                let tx_hash = tx.transaction_hash().unwrap().to_short();
                let packet = Arc::new(AnnounceTx::new(tx_hash));

                self.state = TxSenderState::WaitingResponse(packet.nonce, tx.clone());
                Ok(OutboundPacket::AnnounceTx(packet))
            }

            (TxSenderState::ReadyToSend(nonce, tx), None) => {
                let packet = Arc::new(SendTx::new(*nonce, tx.clone()));

                self.state = TxSenderState::Done;
                Ok(OutboundPacket::SendTx(packet))
            }

            (TxSenderState::Ready, None) => {
                panic!("Invalid data given to sender!");
            }

            (TxSenderState::ReadyToSend(_, _), Some(_)) => {
                panic!("Invalid data given to sender!");
            }

            _ => Err(NetworkErr::CouldNotSend)
        }
    }

    fn acknowledge(&mut self, packet: &InboundPacket) -> Result<(), NetworkErr> {
        match (&self.state, packet) {
            (TxSenderState::WaitingResponse(nonce, _), InboundPacket::RejectTx(packet)) => {
                if nonce == &packet.nonce {
                    self.state = TxSenderState::Done;
                    Ok(())
                } else {
                    Err(NetworkErr::AckErr)
                }
            }

            (TxSenderState::WaitingResponse(nonce, tx), InboundPacket::RequestTx(packet)) => {
                if nonce == &packet.nonce {
                    self.state = TxSenderState::ReadyToSend(*nonce, tx.clone());
                    Ok(())
                } else {
                    Err(NetworkErr::AckErr)
                }
            }

            _ => Err(NetworkErr::SenderStateErr)
        }
    }

    fn can_send(&self) -> bool {
        match self.state {
            TxSenderState::Ready => true,
            TxSenderState::ReadyToSend(_, _) => true,
            _ => false
        }
    }

    fn done(&self) -> bool {
        self.state == TxSenderState::Done
    }

    fn reset(&mut self) {
        self.state = TxSenderState::Ready;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transactions::TestAccount;

    #[test]
    fn it_works_request() {
        let mut sender = TxSender::default();
        assert_eq!(sender.state, TxSenderState::Ready);
        assert!(sender.can_send());

        let tx = transactions::send_coins(TestAccount::A, TestAccount::B, 10, 10, 1);
        let tx = Arc::new(tx);
        
        let packet = sender.send(Some(tx.clone())).unwrap();
        let packet = if let OutboundPacket::AnnounceTx(packet) = packet {
            packet
        } else {
            panic!();
        };
        assert!(!sender.can_send());
        assert_eq!(sender.state, TxSenderState::WaitingResponse(packet.nonce, tx.clone()));

        let request = RequestTx::new(packet.nonce);
        let request = Arc::new(request);
        let inbound = InboundPacket::RequestTx(request);
        sender.acknowledge(&inbound);
        assert!(sender.can_send());
        assert_eq!(sender.state, TxSenderState::ReadyToSend(packet.nonce, tx));

        sender.send(None).unwrap();
        assert!(!sender.can_send());
        assert_eq!(sender.state, TxSenderState::Done);
        sender.reset();
        assert!(sender.can_send());
        assert_eq!(sender.state, TxSenderState::Ready);
    }

    #[test]
    fn it_works_reject() {
        let mut sender = TxSender::default();
        assert_eq!(sender.state, TxSenderState::Ready);

        let tx = transactions::send_coins(TestAccount::A, TestAccount::B, 10, 10, 1);
        let tx = Arc::new(tx);
        
        let packet = sender.send(Some(tx.clone())).unwrap();
        let packet = if let OutboundPacket::AnnounceTx(packet) = packet {
            packet
        } else {
            panic!();
        };
        assert_eq!(sender.state, TxSenderState::WaitingResponse(packet.nonce, tx));
    
        let reject = RejectTx::new(packet.nonce, TxRejectStatus::Witnessed);
        let reject = Arc::new(reject);
        let inbound = InboundPacket::RejectTx(reject);
        sender.acknowledge(&inbound);
        assert_eq!(sender.state, TxSenderState::Done);
        sender.reset();
        assert_eq!(sender.state, TxSenderState::Ready);
    }

    #[test]
    #[should_panic(expected = "Invalid data given to sender!")]
    fn it_panics_on_invalid_data() {
        let mut sender = TxSender::default();
        assert_eq!(sender.state, TxSenderState::Ready);
        sender.send(None);
    }
}