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
use crate::protocol_flow::block_propagation::inbound::InboundPacket;
use crate::protocol_flow::block_propagation::outbound::OutboundPacket;
use crate::protocol_flow::block_propagation::receiver_state::BlockReceiverState;
use crate::validation::receiver::Receiver;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BlockReceiver {
    state: BlockReceiverState,
}

impl Receiver<OutboundPacket, InboundPacket> for BlockReceiver {
    fn receive<N: NetworkInterface>(
        &mut self,
        network: &N,
        _sender: &SocketAddr,
        packet: &OutboundPacket,
    ) -> Result<InboundPacket, NetworkErr> {
        match (&self.state, packet) {
            (BlockReceiverState::Ready, OutboundPacket::AnnounceCheckpoint(packet)) => {
                let chain = network.pow_chain_ref();

                // Check for existence
                if chain.query_orphan_short_hash(&packet.block_hash).is_some()
                    || chain.query_short_hash(&packet.block_hash).is_some()
                {
                    // Reject the block as we have already witnessed it
                    let packet = RejectBlock::new(packet.nonce, BlockRejectStatus::Witnessed);
                    let packet = InboundPacket::RejectBlock(Arc::new(packet));

                    self.state = BlockReceiverState::Done;
                    Ok(packet)
                } else {
                    if let Some(mempool_ref) = network.mempool_ref() {
                        let mempool_count = { mempool_ref.read().count() };
                        let nonce = packet.nonce;
                        let block_hash = packet.block_hash;

                        // Request the announced block
                        let packet = RequestBlock::new(nonce, mempool_count as u32);
                        let packet = InboundPacket::RequestBlock(Arc::new(packet));

                        self.state = BlockReceiverState::WaitingCheckpoint(block_hash, nonce);
                        Ok(packet)
                    } else {
                        unimplemented!();
                    }
                }
            }

            (BlockReceiverState::Ready, OutboundPacket::AnnounceTxBlock(packet)) => {
                let chain = network.pow_chain_ref();

                // Check for existence
                if chain.query_orphan_short_hash(&packet.block_hash).is_some()
                    || chain.query_short_hash(&packet.block_hash).is_some()
                {
                    // Reject the block as we have already witnessed it
                    let packet = RejectBlock::new(packet.nonce, BlockRejectStatus::Witnessed);
                    let packet = InboundPacket::RejectBlock(Arc::new(packet));

                    self.state = BlockReceiverState::Done;
                    Ok(packet)
                } else {
                    if let Some(mempool_ref) = network.mempool_ref() {
                        let mempool_count = { mempool_ref.read().count() };
                        let nonce = packet.nonce;
                        let block_hash = packet.block_hash;

                        // Request the announced block
                        let packet = RequestBlock::new(nonce, mempool_count as u32);
                        let packet = InboundPacket::RequestBlock(Arc::new(packet));

                        self.state = BlockReceiverState::WaitingTxBlock(block_hash, nonce);
                        Ok(packet)
                    } else {
                        unimplemented!();
                    }
                }
            }

            _ => unimplemented!(),
        }
    }

    fn done(&self) -> bool {
        self.state == BlockReceiverState::Done
    }

    fn can_receive(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.state = BlockReceiverState::Ready
    }
}
