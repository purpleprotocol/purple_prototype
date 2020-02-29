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
use crate::interface::NetworkInterface;
use crate::packets::*;
use crate::protocol_flow::transaction_propagation::inbound::InboundPacket;
use crate::protocol_flow::transaction_propagation::outbound::OutboundPacket;
use crate::protocol_flow::transaction_propagation::receiver_state::TxReceiverState;
use crate::validation::receiver::Receiver;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TxReceiver {
    state: TxReceiverState,
}

impl Receiver<OutboundPacket, InboundPacket> for TxReceiver {
    fn receive<N: NetworkInterface>(
        &mut self,
        network: &N,
        _sender: &SocketAddr,
        packet: &OutboundPacket,
    ) -> Result<InboundPacket, NetworkErr> {
        match (&self.state, packet) {
            (TxReceiverState::Ready, OutboundPacket::AnnounceTx(packet)) => {
                if let Some(mempool) = network.mempool_ref() {
                    // Check the existence of the transaction in the mempool
                    let mempool = mempool.read();

                    if mempool.exists(&packet.tx_hash) {
                        // Reject the transaction as it already exists in the mempool
                        let packet = RejectTx::new(packet.nonce, TxRejectStatus::Witnessed);
                        let packet = InboundPacket::RejectTx(Arc::new(packet));

                        self.state = TxReceiverState::Done;
                        Ok(packet)
                    } else {
                        let nonce = packet.nonce;
                        let tx_hash = packet.tx_hash;

                        // Request the announce transaction
                        let packet = RequestTx::new(nonce);
                        let packet = InboundPacket::RequestTx(Arc::new(packet));

                        self.state = TxReceiverState::WaitingTx(nonce, tx_hash);
                        Ok(packet)
                    }
                } else {
                    // Reject the transaction as we have no mempool set
                    let packet = RejectTx::new(packet.nonce, TxRejectStatus::NoMempool);
                    let packet = InboundPacket::RejectTx(Arc::new(packet));

                    self.state = TxReceiverState::Done;
                    Ok(packet)
                }
            }

            (TxReceiverState::WaitingTx(nonce, tx_hash), OutboundPacket::SendTx(packet)) => {
                let received_tx_hash = packet.tx.transaction_hash().unwrap().to_short();

                if packet.nonce == *nonce && *tx_hash == received_tx_hash {
                    // Append the transaction to the mempool
                    let mempool = network.mempool_ref().unwrap();
                    let mut mempool = mempool.write();

                    mempool
                        .append_tx(packet.tx.clone())
                        .map_err(|err| {
                            warn!("Could not append tx {:?}! Reason: {:?}", tx_hash, err)
                        })
                        .unwrap_or(());

                    self.state = TxReceiverState::Done;
                    Ok(InboundPacket::None)
                } else {
                    self.state = TxReceiverState::Done;
                    Err(NetworkErr::AckErr)
                }
            }

            _ => {
                self.state = TxReceiverState::Done;
                Err(NetworkErr::ReceiverStateErr)
            }
        }
    }

    fn done(&self) -> bool {
        self.state == TxReceiverState::Done
    }

    fn can_receive(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.state = TxReceiverState::Ready
    }
}
