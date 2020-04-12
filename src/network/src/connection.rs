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
use crate::network::Network;
use crate::packet::Packet;
use crate::packets::connect::Connect;
use crate::peer::{ConnectionType, Peer, OUTBOUND_BUF_SIZE};
use crate::priority::NetworkPriority;
use crate::validation::sender::Sender;
use crate::util::FuturesIoSock;
use crate::header::PacketHeader as Header;
use crate::client_request::ClientRequest;
use yamux::{Connection, Mode, Config, ConnectionError as YamuxConnErr};
use bytes::{Bytes, BytesMut};
use crypto::{Nonce, Signature};
use persistence::PersistentDb;
use rand::prelude::IteratorRandom;
use std::iter;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use triomphe::Arc;
use std::time::{Duration, Instant};
use std::marker::Unpin;
use tokio::io;
use tokio::net::tcp::ReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use flume::RecvError;
use tokio::time;
use tokio_io_timeout::*;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};

/// Peer timeout interval
pub(crate) const PEER_TIMEOUT: u64 = 15000;

/// Time in milliseconds to poll a peer.
pub(crate) const TIMER_INTERVAL: u64 = 10;

/// A ping will be send at this interval in milliseconds.
pub(crate) const PING_INTERVAL: u64 = 500;

/// Interval in milliseconds for triggering a peer list refresh.
pub(crate) const PEER_REFRESH_INTERVAL: u64 = 3000;

/// Initializes the listener for the given network
pub fn start_listener(network: Network, accept_connections: Arc<AtomicBool>) {
    info!("Starting TCP listener on port {}", network.port());

    let fut = async move {
        // Bind the server's socket.
        let addr: SocketAddr = format!("0.0.0.0:{}", network.port()).parse().unwrap();
        let mut listener: TcpListener = TcpListener::bind(&addr)
            .await
            .expect("unable to bind TCP listener");
        let accept_connections_clone = accept_connections.clone();

        let server = async move {
            loop {
                if !accept_connections_clone.load(Ordering::Relaxed) {
                    continue;
                }

                match listener.accept().await {
                    Ok((s, _addr)) => {
                        if accept_connections_clone.load(Ordering::Relaxed) {
                            continue;
                        }

                        process_connection(
                            network.clone(),
                            s,
                            accept_connections.clone(),
                            ConnectionType::Server,
                        );
                    }

                    Err(err) => {
                        warn!("Couldn't accept connection: {:?}", err);
                    }
                }
            }
        };

        tokio::spawn(server);
    };

    tokio::spawn(fut);
}

pub fn connect_to_peer(network: Network, accept_connections: Arc<AtomicBool>, addr: &SocketAddr) {
    let addr = addr.clone();
    let connect = async move {
        match TcpStream::connect(addr).await {
            Ok(s) => process_connection(network, s, accept_connections, ConnectionType::Client),
            Err(err) => warn!("Failed to connect to peer {}! Reason: {:?}", addr, err),
        }
    };

    tokio::spawn(connect);
}

fn process_connection(
    mut network: Network,
    mut sock: TcpStream,
    accept_connections: Arc<AtomicBool>,
    client_or_server: ConnectionType,
) {
    let socket = async move {
        let refuse_connection = Arc::new(AtomicBool::new(false));
        let addr = sock.peer_addr().unwrap();

        // Wrap raw socket with a `TimeoutStream`
        let mut sock = TimeoutStream::new(sock);
        sock.set_read_timeout(Some(Duration::from_millis(PEER_TIMEOUT)));
        sock.set_write_timeout(Some(Duration::from_millis(PEER_TIMEOUT)));

        // Create outbound channels
        let (low_outbound_sender, mut low_outbound_receiver) = flume::bounded(OUTBOUND_BUF_SIZE);
        let (medium_outbound_sender, mut medium_outbound_receiver) = flume::bounded(OUTBOUND_BUF_SIZE);
        let (high_outbound_sender, mut high_outbound_receiver) = flume::bounded(OUTBOUND_BUF_SIZE);

        // Wrap `TimeoutStream` with futures_io traits wrapper
        let mut sock = FuturesIoSock::new(sock);

        match client_or_server {
            ConnectionType::Client => info!("Connecting to {}", addr),
            ConnectionType::Server => info!("Received connection request from {}", addr),
        };

        // Create new peer and add it to the peer table
        let peer = Peer::new(
            None,
            addr,
            client_or_server,
            Some(low_outbound_sender),
            Some(medium_outbound_sender),
            Some(high_outbound_sender),
            network.bootstrap_cache.clone(),
        );

        let (node_id, skey) = {
            if let Err(NetworkErr::MaximumPeersReached) = network.add_peer(addr, peer) {
                // Stop accepting peers
                accept_connections.store(false, Ordering::Relaxed);
            }

            (network.node_id.clone(), network.secret_key.clone())
        };

        // Write a connect packet if we are the client.
        let connect = match client_or_server {
            ConnectionType::Client => {
                let mut peers = network.peers.read();

                if let Some(peer) = peers.get(&addr) {
                    // Send `Connect` packet.
                    let mut connect = Connect::new(node_id.clone(), peer.pk);
                    connect.sign(&skey);
                    Some(connect)
                } else {
                    warn!("Could not find peer {:?}", addr);
                    return;
                }
            }

            _ => None
        };

        // Send connect packet if we are the client
        if let Some(connect) = connect {
            let packet = async {
                let packet = connect.to_bytes();
                let packet =
                    crate::common::wrap_packet(&packet, network.network_name.as_str());
                packet
            }.await;

            debug!("Sending connect packet to {}", addr);

            if let Err(err) = sock.write(&packet).await {
                warn!("Write to {:?} failed: {:?}", addr, err);
                return;
            }
        }

        // Read `Connect` raw packet
        let packet = match read_raw_packet(&mut sock, &network, &addr, false).await {
            Ok(packet) => packet,
            Err(err) => {
                warn!("Socket reader error for {:?}: {:?}", addr, err);
                ban_peer(&network, &addr);
                return;
            }
        };

        // Parse `Connect` packet
        let connect = match Connect::from_bytes(&packet) {
            Ok(packet) => packet,
            Err(err) => {
                warn!("Connect error for {:?}: {:?}", addr, err);
                ban_peer(&network, &addr);
                return;
            }
        };

        // Handle `Connect` packet
        match Connect::handle(&mut network, &mut sock, &addr, connect, client_or_server).await {
            Ok(()) => { },
            Err(err) => {
                warn!("Connect error for {:?}: {:?}", addr, err);
                ban_peer(&network, &addr);
                return;
            }
        };

        info!("Connected to {}", addr);

        let mode = match client_or_server {
            ConnectionType::Client => Mode::Client,
            ConnectionType::Server => Mode::Server,
        };

        // Wrap socket with multiplexer
        let mut sock = Connection::new(sock, Config::default(), mode);
        let mut control = sock.control();

        let network_clone = network.clone();
        let network_clone2 = network.clone();
        let network_clone3 = network.clone();
        let network_clone4 = network.clone();
        let addr_clone1 = addr.clone();
        let addr_clone2 = addr.clone();

        // Spawn reader and writer futures under a select! macro,
        // terminating both when any of them terminates.
        tokio::select! {
            // Writer future
            _ = async move {
                // Poll outbound channels in the order of their priority
                loop {
                    match high_outbound_receiver.recv_async().await {
                        Ok((packet, req)) => {
                            loop {
                                match control.open_stream().await {
                                    Ok(stream) => {
                                        tokio::spawn(handle_client_stream(network.clone(), stream, packet, req));
                                        break;
                                    }

                                    // Spin until there are streams available
                                    Err(YamuxConnErr::TooManyStreams) => {
                                        tokio::task::yield_now().await;
                                        continue;
                                    }

                                    Err(err) => {
                                        warn!("Opening stream to {:?} failed: {:?}", addr, err);
                                        break;
                                    }
                                };
                            };

                            continue;
                        }

                        Err(RecvError::Disconnected) => {
                            debug!("Write half of {} closed", addr);
                            break;
                        }
                    }

                    match medium_outbound_receiver.recv_async().await {
                        Ok((packet, req)) => {
                            loop {
                                match control.open_stream().await {
                                    Ok(stream) => {
                                        tokio::spawn(handle_client_stream(network.clone(), stream, packet, req));
                                        break;
                                    }

                                    // Spin until there are streams available
                                    Err(YamuxConnErr::TooManyStreams) => {
                                        tokio::task::yield_now().await;
                                        continue;
                                    }

                                    Err(err) => {
                                        warn!("Opening stream to {:?} failed: {:?}", addr, err);
                                        break;
                                    }
                                };
                            };

                            continue;
                        }

                        Err(RecvError::Disconnected) => {
                            debug!("Write half of {} closed", addr);
                            break;
                        }
                    }

                    match low_outbound_receiver.recv_async().await {
                        Ok((packet, req)) => {
                            loop {
                                match control.open_stream().await {
                                    Ok(stream) => {
                                        tokio::spawn(handle_client_stream(network.clone(), stream, packet, req));
                                        break;
                                    }

                                    // Spin until there are streams available
                                    Err(YamuxConnErr::TooManyStreams) => {
                                        tokio::task::yield_now().await;
                                        continue;
                                    }

                                    Err(err) => {
                                        warn!("Opening stream to {:?} failed: {:?}", addr, err);
                                        break;
                                    }
                                };
                            };

                            continue;
                        }

                        Err(RecvError::Disconnected) => {
                            debug!("Write half of {} closed", addr);
                            break;
                        }
                    }
                }
            } => {
                let network = network_clone3;

                network.remove_peer_with_addr(&addr);

                // Re-enable connections
                if network.peer_count() < network.max_peers {
                    accept_connections.store(true, Ordering::Relaxed);
                }

                debug!("Writer for {} closed", addr_clone1);
            }

            // Reader future
            _ = async move {
                loop {
                    let network = network_clone2.clone();

                    match sock.next_stream().await {
                        Ok(Some(stream)) => {
                            debug!("Starting server tcp stream with id {} for {}", stream.id(), addr);

                            tokio::spawn(async move {
                                let network = network.clone();

                                handle_server_stream(&network, &stream)
                                    .await
                                    .map_err(|err| warn!("Socket reader error for {:?}: {:?}", addr, err));
                            });
                        }

                        _ => {
                            break;
                        }
                    }
                };

                info!("Connection to {} closed", addr);
            } => {
                let network = network_clone4;

                network.remove_peer_with_addr(&addr);

                // Re-enable connections
                if network.peer_count() < network.max_peers {
                    accept_connections.store(true, Ordering::Relaxed);
                }

                debug!("Reader for {} closed", addr_clone2);
            }
        };
    };

    tokio::spawn(socket);
}

async fn handle_client_stream<N: NetworkInterface, S: AsyncWrite + AsyncWriteExt + AsyncRead + AsyncReadExt + Unpin>(
    network: N,
    sock: S,
    initial_packet: Vec<u8>,
    client_request: ClientRequest,
) -> Result<(), NetworkErr> {
    // Write initial packet to stream

    unimplemented!();
}

async fn handle_server_stream<N: NetworkInterface, S: AsyncWrite + AsyncWriteExt + AsyncRead + AsyncReadExt + Unpin>(
    network: &N,
    sock: &S,
) -> Result<(), NetworkErr> {
    unimplemented!();
}

/// Attempt to decode a `Header` from a socket
async fn read_header<S: AsyncRead + AsyncReadExt + Unpin>(socket: &mut S, addr: &SocketAddr) -> Result<Header, io::Error> {
    let mut header_buf: [u8; crate::common::HEADER_SIZE] = [0; crate::common::HEADER_SIZE];

    // Read header
    socket.read_exact(&mut header_buf).await?;

    // Decode header
    let header = crate::common::decode_header(&header_buf).map_err(|err| {
        // TODO: Handle header read error
        io::Error::new(
            io::ErrorKind::Other,
            format!("Header read error for {}: {:?}", addr, err),
        )
    })?;

    // Only accept our current network version
    if header.network_version != crate::common::NETWORK_VERSION {
        return Err(io::Error::new(
            // TODO: Handle header read error
            io::ErrorKind::Other,
            format!(
                "Header read error for {}: {:?}",
                addr,
                NetworkErr::BadVersion
            ),
        ));
    }

    Ok(header)
}

/// Attempts to read and decode a raw packet from the given socket 
async fn read_raw_packet<N: NetworkInterface, S: AsyncRead + AsyncReadExt + Unpin>(
    sock: &mut S,
    network: &N,
    addr: &SocketAddr,
    decrypt: bool,
) -> Result<Bytes, io::Error> {
    // Read header
    let header = read_header(sock, addr).await?;

    // Read packet from socket
    let mut packet_buf = BytesMut::with_capacity(header.packet_len as usize);
    sock.read_exact(&mut packet_buf).await?;

    let bytes_read = packet_buf.len();

    // Account bytes read
    account_bytes_read(network.clone(), &addr.clone(), bytes_read).await;

    // Verify packet CRC32
    verify_crc32(network, addr, &header, &packet_buf).await?;

    if decrypt {
        // Decrypt packet
        decrypt_packet(network, addr, &header, packet_buf).await
    } else {
        Ok(packet_buf.freeze())
    }
}

async fn verify_crc32<N: NetworkInterface>(network: &N, addr: &SocketAddr, header: &Header, buf: &BytesMut) -> Result<(), io::Error> {
    crate::common::verify_crc32(&header, &buf, network.network_name())
        .map_err(|err| {
            io::Error::new(
                // TODO: Handle header read error
                io::ErrorKind::Other,
                format!("Header read error for {}: {:?}", addr, err),
            )
        })
}

async fn decrypt_packet<N: NetworkInterface>(network: &N, addr: &SocketAddr, header: &Header, buf: BytesMut) -> Result<Bytes, io::Error> {
    let (peer_id, peer_tx) = { 
        let peers = network.peers();
        let peers = peers.read();
        let peer = peers.get(&addr).ok_or(io::Error::new(
                io::ErrorKind::Other,
                format!("Lost connection to {}", addr),
            ))?;

        (peer.id.clone(), peer.tx.clone())
    };

    let mut buf = BytesMut::new();

    // Decode nonce which is always the
    // first 12 bytes in the packet.
    let nonce_buf = &buf[..12];
    let mut nonce: [u8; 12] = [0; 12];
    nonce.copy_from_slice(nonce_buf);
    let nonce = Nonce(nonce);

    // The next 64 bytes in the packet are
    // the signature of the packet.
    let sig_buf = &buf[12..76];
    let sig = Signature::new(sig_buf);

    // Get a slice of the remaining length
    // which is the packet payload.
    let packet_slice = &buf[76..];

    // Verify packet signature
    if !crypto::verify(packet_slice, &sig, &peer_id.as_ref().unwrap().0) {
        return Err(io::Error::new(
            // TODO: Handle signature error
            io::ErrorKind::Other,
            format!("Packet signature error for {}", addr),
        ));
    }

    // Decrypt payload
    let decrypted =
        crate::common::decrypt(packet_slice, &nonce, peer_tx.as_ref().unwrap())
            .map_err(|_| {
                io::Error::new(
                    // TODO: Handle encryption error
                    io::ErrorKind::Other,
                    format!("Encryption error for {}", addr),
                )
            })?;

    buf.extend_from_slice(&decrypted);
    Ok(buf.freeze())
}

async fn account_bytes_read<N: NetworkInterface>(network: N, addr: &SocketAddr, bytes_read: usize) {
    let bytes_read = bytes_read + crate::common::HEADER_SIZE;
    let acc = {
        let peers = network.peers();
        let peers = peers.read();

        if let Some(peer) = peers.get(addr) {
            peer.bytes_read.clone()
        } else {
            warn!("Could not find peer {}", addr);
            return;
        }
    };

    debug!("Finished reading {} bytes from {}", bytes_read, addr);
    acc.fetch_add(bytes_read as u64, Ordering::SeqCst);
}

async fn handle_err<N: NetworkInterface>(network: &N, addr: &SocketAddr, refuse_connection: Arc<AtomicBool>, result: Result<(), NetworkErr>) {
    // TODO: Handle other errors as well
    match result {
        Ok(_) => {} // Do nothing
        Err(NetworkErr::InvalidConnectPacket) => {
            // Flag socket for connection refusal if we
            // have received an invalid connect packet.
            refuse_connection.store(true, Ordering::Relaxed);

            // Also, ban the peer
            ban_peer(network, addr);
        }

        Err(NetworkErr::SelfConnect) => {
            refuse_connection.store(true, Ordering::Relaxed);
        }

        err => {
            warn!("Packet process error for {}: {:?}", addr.clone(), err);
            ban_peer(network, addr); // Blanket ban for now
        }
    }
}

/// Starts a background job responsible for requesting and
/// connecting to peers when we aren't connected to the maximum
/// number of peers.
pub fn start_peer_list_refresh_interval(
    mut network: Network,
    accept_connections: Arc<AtomicBool>,
    db: PersistentDb,
    max_peers: usize,
    bootnodes: Vec<SocketAddr>,
    port: u16,
) {
    debug!("Starting peer list refresh interval...");

    let refresh_interval = async move {
        let mut refresh_interval = time::interval(Duration::from_millis(PEER_REFRESH_INTERVAL));

        loop {
            refresh_interval.tick().await;

            debug!("Triggering peer refresh...");

            let peers = network.peers();
            let peers = peers.read();

            if peers.len() < network.max_peers {
                debug!(
                    "We are missing {} peers, requesting more peers...",
                    network.max_peers - peers.len()
                );

                // Choose a random node to request peers from.
                // TODO: Ask multiple peers
                let peer = peers
                    .iter()
                    .map(|(addr, _)| addr.clone())
                    .choose(&mut rand::thread_rng());

                if let Some(peer_addr) = peer {
                    debug!("Requesting peers from {}", peer_addr);

                    let missing_peers = network.max_peers - peers.len();
                    let peer = peers.get(&peer_addr).unwrap();
                    let sender = peer.validator.request_peers.sender.clone();

                    let result = {
                        let mut sender = sender.lock();

                        sender.send(missing_peers as u8).map_err(|err| {
                            warn!("Could not send packet to {}, reason: {:?}", peer_addr, err)
                        })
                    };

                    if let Ok(packet) = result {
                        network
                            .send_to_peer(&peer_addr, &packet, NetworkPriority::Medium)
                            .map_err(|err| {
                                warn!("Could not send packet to {}, reason: {:?}", peer_addr, err)
                            })
                            .unwrap_or(());
                    }
                } else {
                    debug!("No connections available! Fallback to bootstrap script...");
                    crate::bootstrap::bootstrap(
                        network.clone(),
                        accept_connections.clone(),
                        db.clone(),
                        max_peers,
                        bootnodes.clone(),
                        port,
                        false,
                    );
                }
            } else if peers.len() == network.max_peers {
                debug!("We have enough peers. No need to refresh the peer list");
            } else {
                debug!(
                    "More peers than needed found! Disconnecting from {} peers.",
                    peers.len() - network.max_peers
                );

                // TODO: Disconnect from the peers with the highest latency
                let iter = peers
                    .iter()
                    .filter_map(|(_, p)| p.id.as_ref())
                    .take(peers.len() - network.max_peers);

                for id in iter {
                    network
                        .disconnect(id)
                        .map_err(|err| {
                            warn!(
                                "Could not disconnect from peer with id {:?}! Reason: {:?}",
                                id, err
                            )
                        })
                        .unwrap_or(());
                }
            }
        }
    };

    tokio::spawn(refresh_interval);
}

// async fn socket_reader(
//     mut network: Network,
//     addr: SocketAddr,
//     mut reader: BufReader<TimeoutReader<ReadHalf<'_>>>,
//     refuse_connection: Arc<AtomicBool>,
// ) -> Result<(), io::Error> {
//     let mut header_buf: [u8; crate::common::HEADER_SIZE] = [0; crate::common::HEADER_SIZE];

//     loop {
//         if refuse_connection.load(Ordering::Relaxed) {
//             info!("Closing connection to {:?}", addr);
//             break;
//         }

//         // Process packet
//         let result = async { network.process_packet(&addr, &packet) }.await;

//         // Handle any error
//         handle_err(&network, &addr, refuse_connection.clone(), result).await;
//     }

//     Ok(())
// }

fn ban_peer<N: NetworkInterface>(network: &N, addr: &SocketAddr) {
    info!("Banning peer {}", addr);
    network.ban_ip(&addr).unwrap();
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_timeouts() {

//     }
// }
