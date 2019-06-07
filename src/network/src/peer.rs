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

use crypto::{gen_kx_keypair, KxPublicKey as Pk, KxSecretKey as Sk, SessionKey};
use std::net::SocketAddr;
use std::hash::{Hash, Hasher};
use std::collections::VecDeque;
use NodeId;

#[derive(Clone, Debug, Copy)]
pub enum ConnectionType {
    Client,
    Server,
}

/// Size of the outbound buffer.
pub const OUTBOUND_BUF_SIZE: usize = 1000;

#[derive(Debug, Clone)]
pub struct Peer {
    /// The id of the peer
    ///
    /// An option is used in order to store the peer's
    /// session before a connect packet containing the
    /// node's id has been received.
    pub id: Option<NodeId>,

    /// The type of the connection. Can be 
    /// either `Client` or `Server`.
    /// 
    /// A connection type is `Client` when
    /// we are the one connecting.
    /// 
    /// A connection type is `Server` when
    /// a peer connects to us.
    pub connection_type: ConnectionType,

    /// The ip address of the peer
    pub ip: SocketAddr,

    /// Wether the peer has send a `Connect` packet or not.
    pub sent_connect: bool,

    /// Wether we have asked the peer to send us a peer list 
    /// and the number of peers that we have requested.
    pub requested_peers: Option<u8>,

    /// Buffer storing packets that are to be 
    /// sent to the peer.
    pub outbound_buffer: VecDeque<Vec<u8>>,

    /// Session generated public key
    pub pk: Pk,

    /// Session generated secret key
    pub(crate) sk: Sk,

    /// Our encryption key
    pub(crate) rx: Option<SessionKey>,

    /// The peer's encryption key
    pub (crate) tx: Option<SessionKey>,
}

impl Peer {
    pub fn new(id: Option<NodeId>, ip: SocketAddr, connection_type: ConnectionType) -> Peer {
        let (pk, sk) = gen_kx_keypair();
        let outbound_buffer = VecDeque::with_capacity(OUTBOUND_BUF_SIZE);

        Peer {
            id: id,
            ip: ip,
            pk: pk,
            sk: sk,
            rx: None,
            tx: None,
            requested_peers: None,
            sent_connect: false,
            connection_type,
            outbound_buffer,
        }
    }

    /// Sets the id of the peer to the given value
    pub fn set_id(&mut self, id: NodeId) {
        self.id = Some(id);
    }

    /// Sets the session keys associated with the peer
    pub fn set_session_keys(&mut self, rx: SessionKey, tx: SessionKey) {
        self.rx = Some(rx);
        self.tx = Some(tx);
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Peer) ->  bool {
        match (&self.id, &other.id) {
            // Check both ids and ips
            (Some(id1), Some(id2)) => id1 == id2 && self.ip == other.ip,
            // Fallback to just comparing ips
            (_, _) => self.ip == other.ip,
        }
    }
}

impl Eq for Peer {}

impl Hash for Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(id) = &self.id {
            id.hash(state);
        }
        self.ip.hash(state);
    }
}
