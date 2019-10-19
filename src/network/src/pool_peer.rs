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

use crate::error::NetworkErr;
use crate::validation::validator::ProtocolValidator;
use crate::bootstrap::cache::BootstrapCache;
use crypto::NodeId;
use crypto::{gen_kx_keypair, KxPublicKey as Pk, KxSecretKey as Sk, SessionKey};
use std::default::Default;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use peer::ConnectionType;

#[cfg(test)]
use parking_lot::Mutex;

#[cfg(test)]
use timer::{Guard, Timer};

/// Size of the outbound buffer.
pub const OUTBOUND_BUF_SIZE: usize = 10000;

#[derive(Clone, Copy, Debug, PartialEq)]
enum SessionState {
    /// We are connected to a potential validator but have not yet determined
    /// the validity of its validator status.
    PreValidation,

    /// The validator is waiting to join the pool in the assigned epoch.
    WaitingToJoin(u64),

    /// The validator is currently active.
    Active,

    /// The validator is still connected but his session in the pool is finished.
    Finished,

    /// The validator has been found to be unresponsive or byzantine and
    /// has been kicked out of the pool.
    Kicked,
}

#[derive(Clone)]
pub struct PoolPeer {
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

    /// Wether the peer has sent a `Connect` packet or not.
    pub sent_connect: bool,

    /// Buffer storing packets that are to be
    /// sent to the peer.
    pub outbound_buffer: Option<Sender<Vec<u8>>>,

    /// Session generated public key
    pub pk: Pk,

    /// Peer session state
    session_state: SessionState,

    /// Session generated secret key
    pub(crate) sk: Sk,

    /// Our encryption key
    pub(crate) rx: Option<SessionKey>,

    /// The peer's encryption key
    pub(crate) tx: Option<SessionKey>,

    /// Associated protocol validator
    pub(crate) validator: ProtocolValidator,
}

impl fmt::Debug for PoolPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PoolPeer(id: {:?}, ip: {:?})", self.id, self.ip)
    }
}

impl PoolPeer {
    pub fn new(
        id: Option<NodeId>,
        ip: SocketAddr,
        connection_type: ConnectionType,
        outbound_buffer: Option<Sender<Vec<u8>>>,
        bootstrap_cache: BootstrapCache,
        start_epoch: u64,
    ) -> PoolPeer {
        let (pk, sk) = gen_kx_keypair();

        PoolPeer {
            id: id,
            ip: ip,
            pk: pk,
            sk: sk,
            rx: None,
            tx: None,
            sent_connect: false,
            connection_type,
            outbound_buffer,
            session_state: SessionState::WaitingToJoin(start_epoch),
            last_seen: Arc::new(AtomicU64::new(0)),
            last_ping: Arc::new(AtomicU64::new(0)),
            validator: ProtocolValidator::new(bootstrap_cache),
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

    /// Attempts to place a packet in the outbound buffer of a `PoolPeer`.
    pub fn send_packet(&self, packet: Vec<u8>) -> Result<(), NetworkErr> {
        let mut sender = self.outbound_buffer.as_ref().unwrap().clone();
        sender
            .try_send(packet)
            .map_err(|err| { debug!("Packet sending error: {:?}", err); NetworkErr::CouldNotSend })
    }
}

impl PartialEq for PoolPeer {
    fn eq(&self, other: &PoolPeer) -> bool {
        match (&self.id, &other.id) {
            // Check both ids and ips
            (Some(id1), Some(id2)) => id1 == id2 && self.ip == other.ip,
            // Fallback to just comparing ips
            (_, _) => self.ip == other.ip,
        }
    }
}

impl Eq for PoolPeer {}

impl Hash for PoolPeer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(id) = &self.id {
            id.hash(state);
        }
        self.ip.hash(state);
    }
}
