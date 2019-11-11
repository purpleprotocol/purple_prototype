/*
  Copyright (C) 2018-2019 The Purple Core Developers.
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

use crate::pool_peer::{PoolPeer, SessionState};
use crate::error::NetworkErr;
use crate::validation::validator::ProtocolValidator;
use crate::bootstrap::cache::BootstrapCache;
use crate::validation::pool_validator::PoolProtocolValidator;
use crypto::{Hash, NodeId};
use crypto::{gen_kx_keypair, KxPublicKey as Pk, KxSecretKey as Sk, SessionKey};
use std::default::Default;
use std::fmt;
use std::hash::{Hash as HashTrait, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

#[cfg(test)]
use parking_lot::Mutex;

#[cfg(test)]
use timer::{Guard, Timer};

#[derive(Clone, Debug, Copy)]
pub enum ConnectionType {
    Client(SubConnectionType),
    Server,
}

#[derive(Clone, Debug, Copy)]
/// Sub-connection type used as flag for connection processing
/// when we are connecting as `Client`. In the case of the `Server`
/// type, this is determined at run-time.
pub enum SubConnectionType {
    /// Normal connection
    Normal,

    /// Validator connection with sub-field containing the hash
    /// of the miner PoW block.
    Validator(Hash),
}

/// Size of the outbound buffer.
pub const OUTBOUND_BUF_SIZE: usize = 10000;

#[derive(Clone)]
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

    /// Time in milliseconds since the peer has last sent a message.
    pub last_seen: Arc<AtomicU64>,

    /// Time in milliseconds since we have sent a ping to the peer.
    pub last_ping: Arc<AtomicU64>,

    /// Whether the peer has sent a `Connect` packet or not.
    pub sent_connect: bool,

    /// Buffer storing packets that are to be
    /// sent to the peer.
    pub outbound_buffer: Option<Sender<Vec<u8>>>,

    /// Session generated public key
    pub pk: Pk,

    /// Session generated secret key
    pub(crate) sk: Sk,

    /// Our encryption key
    pub(crate) rx: Option<SessionKey>,

    /// The peer's encryption key
    pub(crate) tx: Option<SessionKey>,

    /// Associated protocol validator
    pub(crate) validator: ProtocolValidator,

    #[cfg(test)]
    pub(crate) timeout_guard: Option<Guard>,

    #[cfg(test)]
    pub(crate) timer: Option<Arc<Mutex<Timer>>>,

    #[cfg(test)]
    pub(crate) send_ping: bool,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Peer(id: {:?}, ip: {:?})", self.id, self.ip)
    }
}

impl Peer {
    pub fn new(
        id: Option<NodeId>,
        ip: SocketAddr,
        connection_type: ConnectionType,
        outbound_buffer: Option<Sender<Vec<u8>>>,
        bootstrap_cache: BootstrapCache,
    ) -> Peer {
        let (pk, sk) = gen_kx_keypair();

        match connection_type {
            ConnectionType::Client(SubConnectionType::Validator(_)) => {
                panic!("Cannot create a normal peer with the validator sub-connection type!");
            }
            _ => { } // Do nothing
        }

        Peer {
            id: id,
            ip: ip,
            pk: pk,
            sk: sk,
            rx: None,
            tx: None,
            sent_connect: false,
            connection_type,
            outbound_buffer,
            last_seen: Arc::new(AtomicU64::new(0)),
            last_ping: Arc::new(AtomicU64::new(0)),
            validator: ProtocolValidator::new(bootstrap_cache),

            #[cfg(test)]
            timeout_guard: None,

            #[cfg(test)]
            timer: None,

            #[cfg(test)]
            send_ping: true,
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

    /// Attempts to place a packet in the outbound buffer of a `Peer`.
    pub fn send_packet(&self, packet: Vec<u8>) -> Result<(), NetworkErr> {
        let mut sender = self.outbound_buffer.as_ref().unwrap().clone();
        sender
            .try_send(packet)
            .map_err(|err| { debug!("Packet sending error: {:?}", err); NetworkErr::CouldNotSend })
    }

    /// Consumes a `Peer` struct and returns a `PeerPool` struct
    /// that can be appended to a validator network peer table.
    pub fn to_validator(self) -> PoolPeer {
        PoolPeer {
            rx: self.rx,
            tx: self.tx,
            pk: self.pk,
            sk: self.sk,
            id: self.id,
            ip: self.ip,
            last_seen: self.last_seen,
            last_ping: self.last_ping,
            connection_type: self.connection_type,
            outbound_buffer: self.outbound_buffer,
            session_state: SessionState::PreValidation,
            validator: PoolProtocolValidator::new(),
        }
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        match (&self.id, &other.id) {
            // Check both ids and ips
            (Some(id1), Some(id2)) => id1 == id2 && self.ip == other.ip,
            // Fallback to just comparing ips
            (_, _) => self.ip == other.ip,
        }
    }
}

impl Eq for Peer {}

impl HashTrait for Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(id) = &self.id {
            id.hash(state);
        }
        self.ip.hash(state);
    }
}
