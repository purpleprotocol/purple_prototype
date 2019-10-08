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

use crate::common;
use crate::error::NetworkErr;
use crate::interface::NetworkInterface;
use crate::network::Network;
use crate::packet::Packet;
use crate::packets::connect::Connect;
use crate::peer::{ConnectionType, Peer, OUTBOUND_BUF_SIZE};
use crate::validation::sender::Sender;
use crypto::{Nonce, Signature};
use std::io::BufReader;
use std::iter;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, Duration};
use tokio::executor::Spawn;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::future::{err, ok};
use tokio::prelude::*;
use tokio::sync::mpsc;
use tokio_io_timeout::TimeoutStream;
use tokio_timer::Interval;
use rand::prelude::IteratorRandom;

/// Peer timeout interval
const PEER_TIMEOUT: u64 = 15000;

/// Time in milliseconds to poll a peer.
const TIMER_INTERVAL: u64 = 10;

/// A ping will be send at this interval in milliseconds.
const PING_INTERVAL: u64 = 500;

/// Interval in milliseconds for triggering a peer list refresh.
const PEER_REFRESH_INTERVAL: u64 = 10000;

/// Initializes the listener for the given network
pub fn start_listener(network: Network, accept_connections: Arc<AtomicBool>) -> Spawn {
    info!("Starting TCP listener on port {}", network.port());

    // Bind the server's socket.
    let addr = format!("0.0.0.0:{}", network.port()).parse().unwrap();
    let listener = TcpListener::bind(&addr).expect("unable to bind TCP listener");
    let accept_connections_clone = accept_connections.clone();

    // Pull out a stream of sockets for incoming connections
    let server = listener
        .incoming()
        .map_err(|e| warn!("accept failed = {:?}", e))
        .filter(move |_| accept_connections_clone.load(Ordering::Relaxed))
        .for_each(move |s| {
            process_connection(
                network.clone(),
                s,
                accept_connections.clone(),
                ConnectionType::Server,
            )
        });

    tokio::spawn(server)
}

pub fn connect_to_peer(
    network: Network,
    accept_connections: Arc<AtomicBool>,
    addr: &SocketAddr,
) -> Spawn {
    let connect = TcpStream::connect(addr)
        .map_err(|e| warn!("connect failed = {:?}", e))
        .and_then(move |sock| {
            process_connection(network, sock, accept_connections, ConnectionType::Client)
        });

    tokio::spawn(connect)
}

fn process_connection(
    mut network: Network,
    sock: TcpStream,
    accept_connections: Arc<AtomicBool>,
    client_or_server: ConnectionType,
) -> Spawn {
    let mut sock = TimeoutStream::new(sock);

    // Set timeout
    sock.set_read_timeout(Some(Duration::from_millis(PEER_TIMEOUT)));
    sock.set_write_timeout(Some(Duration::from_millis(PEER_TIMEOUT)));

    let refuse_connection = Arc::new(AtomicBool::new(false));
    let addr = sock.get_ref().peer_addr().unwrap();

    match client_or_server {
        ConnectionType::Client => info!("Connecting to {}", addr),
        ConnectionType::Server => info!("Received connection request from {}", addr),
    };

    // Create outbound channel
    let (outbound_sender, outbound_receiver) = mpsc::channel(OUTBOUND_BUF_SIZE);

    // Create new peer and add it to the peer table
    let peer = Peer::new(None, addr, client_or_server, Some(outbound_sender), network.bootstrap_cache.clone());

    let (node_id, skey) = {
        if let Err(NetworkErr::MaximumPeersReached) = network.add_peer(addr, peer.clone()) {
            // Stop accepting peers
            accept_connections.store(false, Ordering::Relaxed);
        }

        (network.node_id.clone(), network.secret_key.clone())
    };

    // Split up the reading and writing parts of the
    // socket.
    let (reader, writer) = sock.split();
    let reader = BufReader::new(reader);
    let network_clone = network.clone();
    let network_clone2 = network.clone();

    // Model the read portion of this socket by mapping an infinite
    // iterator to each line off the socket. This "loop" is then
    // terminated with an error once we hit EOF on the socket.
    let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));
    let refuse_connection_clone = refuse_connection.clone();
    let socket_writer = ok(network.clone())
        .and_then(move |network| {
            let mut writer = writer;

            {
                let mut peers = network.peers.write();

                if let Some(peer) = peers.get_mut(&addr) {
                    // Write a connect packet if we are the client.
                    if let ConnectionType::Client = client_or_server {
                        // Send `Connect` packet.
                        let mut connect = Connect::new(node_id.clone(), peer.pk);
                        connect.sign(&skey);

                        let packet = connect.to_bytes();
                        let packet =
                            crate::common::wrap_packet(&packet, network.network_name.as_str());
                        debug!("Sending connect packet to {}", addr);

                        writer
                            .poll_write(&packet)
                            .map_err(|err| warn!("write failed = {:?}", err))
                            .and_then(|_| Ok(()))
                            .unwrap();
                    }
                } else {
                    return err("no peer found");
                }
            }

            ok((writer, network))
        })
        .and_then(move |(writer, network)| {
            let fut = outbound_receiver.map_err(|err| format!("{}", err)).fold(
                writer,
                move |mut writer, packet| {
                    let peers = network.peers.read();

                    if peers.get(&addr).is_some() {
                        writer
                            .poll_write(&packet)
                            .map_err(|err| warn!("write failed = {:?}", err))
                            .and_then(|_| Ok(()))
                            .unwrap_or(());

                        ok(writer)
                    } else {
                        err("no peer found")
                    }
                },
            );

            tokio::spawn(fut.then(move |_| {
                debug!("Write half of {} closed", addr);
                Ok(())
            }));

            ok(())
        });

    let socket_reader = iter
        .take_while(move |_| ok(!refuse_connection_clone.load(Ordering::Relaxed)))
        .fold((reader, network.clone()), move |(reader, network), _| {
            // Read header
            let line = io::read_exact(reader, vec![0; common::HEADER_SIZE])
                // Decode header
                .and_then(move |(reader, buffer)| {
                    let header = common::decode_header(&buffer).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("Header read error for {}: {:?}", addr, err),
                        )
                    })?;

                    // Only accept our current network version
                    if header.network_version != common::NETWORK_VERSION {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "Header read error for {}: {:?}",
                                addr,
                                NetworkErr::BadVersion
                            ),
                        ));
                    }

                    Ok((reader, network, header))
                })
                // Read packet from stream
                .and_then(move |(reader, network, header)| {
                    io::read_exact(reader, vec![0; header.packet_len as usize])
                        .map(|(reader, buffer)| (reader, network, header, buffer))
                })
                // Verify crc32 checksum
                .and_then(move |(reader, network, header, buffer)| {
                    common::verify_crc32(&header, &buffer, network.network_name.as_str()).map_err(
                        |err| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("Header read error for {}: {:?}", addr, err),
                            )
                        },
                    )?;

                    Ok((reader, network, header, buffer))
                })
                // Decrypt packet
                .and_then(move |(reader, network, header, buffer)| {
                    let packet: Vec<u8> = {
                        let mut peers = network.peers.write();

                        if let Some(peer) = peers.get_mut(&addr) {
                            let mut buf: Vec<u8> = Vec::new();

                            // Decrypt packet if we are connected
                            if peer.sent_connect {
                                // Decode nonce which is always the
                                // first 12 bytes in the packet.
                                let (nonce_buf, buffer) = buffer.split_at(12);
                                let mut nonce: [u8; 12] = [0; 12];
                                nonce.copy_from_slice(&nonce_buf);
                                let nonce = Nonce(nonce);

                                // The next 64 bytes in the packet are
                                // the signature of the packet.
                                let (sig_buf, buffer) = buffer.split_at(64);
                                let sig = Signature::new(&sig_buf);

                                // Verify packet signature
                                if !crypto::verify(&buffer, &sig, &peer.id.as_ref().unwrap().0) {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("Packet signature error for {}", addr),
                                    ));
                                }

                                buf = common::decrypt(&buffer, &nonce, peer.tx.as_ref().unwrap())
                                    .map_err(|_| {
                                        io::Error::new(
                                            io::ErrorKind::Other,
                                            format!("Encryption error for {}", addr),
                                        )
                                    })?;
                            } else {
                                // We are expecting an un-encrypted `Connect` packet
                                // so we make it just pass through.
                                buf = buffer;
                            }

                            buf
                        } else {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("Lost connection to {}", addr),
                            ));
                        }
                    };

                    Ok((reader, network, header, packet))
                })
                .and_then(move |(reader, network, _, vec)| {
                    if vec.len() == 0 {
                        Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
                    } else {
                        Ok((reader, network, vec))
                    }
                });

            let refuse_connection = refuse_connection.clone();

            line.map(move |(reader, mut network, message)| {
                let result = network.process_packet(&addr, &message);
                (reader, network, result)
            })
            .map(move |(reader, network, result)| {
                // TODO: Handle other errors as well
                match result {
                    Ok(_) => {} // Do nothing
                    Err(NetworkErr::InvalidConnectPacket) => {
                        // Flag socket for connection refusal if we
                        // have received an invalid connect packet.
                        refuse_connection.store(true, Ordering::Relaxed);

                        // Also, ban the peer
                        info!("Banning peer {}", addr);
                        network.ban_ip(&addr).unwrap();
                    }

                    Err(NetworkErr::SelfConnect) => {
                        refuse_connection.store(true, Ordering::Relaxed);
                    }

                    err => {
                        warn!("Packet process error for {}: {:?}", addr.clone(), err);
                    }
                }

                (reader, network)
            })
        });

    let peers_clone = network.peers.clone();
    let addr_clone = addr.clone();
    let addr_clone2 = addr.clone();

    // Spawn a repeating task at a given interval for this peer
    let peer_interval = Interval::new_interval(Duration::from_millis(TIMER_INTERVAL))
        .take_while(move |_| ok(network_clone.has_peer(&addr)))
        .fold(0, move |mut times_denied, _| {
            let peers = peers_clone.clone();
            let addr = addr_clone.clone();
            let peers = peers.read();
            let peer = peers.get(&addr).unwrap();

            let _ = peer.last_seen.fetch_add(TIMER_INTERVAL, Ordering::SeqCst);
            let last_ping = peer.last_ping.fetch_add(TIMER_INTERVAL, Ordering::SeqCst);

            if last_ping > PING_INTERVAL {
                {
                    let mut sender = peer.validator.ping_pong.sender.lock();

                    if let Ok(ping) = sender.send(()) {
                        peer.last_ping.store(0, Ordering::SeqCst);

                        debug!("Sending Ping packet to {}", addr);

                        network_clone2
                            .send_to_peer(&addr, ping.to_bytes())
                            .map_err(|err| warn!("Could not send ping to {}: {:?}", addr, err))
                            .unwrap_or(());

                        debug!("Sent Ping packet to {}", addr);
                    } else {
                        times_denied += 1;

                        // Reset sender if it's stuck
                        if times_denied > 10 {
                            times_denied = 0;
                            sender.reset();
                        }
                    }
                }
            }

            ok(times_denied)
        })
        .map_err(move |e| {
            warn!("Peer interval error for {}: {}", addr, e);
            ()
        })
        .and_then(move |_| {
            debug!("Peer interval timer for {} has finished!", addr_clone2);
            Ok(())
        });

    // Now that we've got futures representing each half of the socket, we
    // use the `select` combinator to wait for either half to be done to
    // tear down the other. Then we spawn off the result.
    let socket_reader = socket_reader.map_err(|e| {
        warn!("{}", e);
        ()
    });
    let socket_writer = socket_writer.map_err(|e| {
        warn!("Socket write error: {}", e);
        ()
    });

    let accept_connections = accept_connections.clone();

    // Spawn a task to process the connection
    tokio::spawn(socket_reader.then(move |_| {
        network.remove_peer_with_addr(&addr);

        // Re-enable connections
        if network.peer_count() < network.max_peers {
            accept_connections.store(true, Ordering::Relaxed);
        }

        info!("Connection to {} closed", addr);
        ok(())
    }));

    tokio::spawn(socket_writer);
    tokio::spawn(peer_interval)
}

/// Starts a background job responsible for requesting and
/// connecting to peers when we aren't connected to the maximum
/// number of peers.
pub fn start_peer_list_refresh_interval(network: Network) -> Spawn {
    debug!("Starting peer list refresh interval...");

    let refresh_interval = Interval::new(Instant::now(), Duration::from_millis(PEER_REFRESH_INTERVAL))
        .fold(network, move |mut network, _| {
            debug!("Triggering peer refresh...");

            let peers = network.peers();
            let peers = peers.read();

            if peers.len() < network.max_peers {
                debug!("We are missing {} peers, requesting more peers...", network.max_peers - peers.len());

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
                    let mut sender = sender.lock();
                    let result = sender
                        .send(missing_peers as u8)
                        .map_err(|err| warn!("Could not send packet to {}, reason: {:?}", peer_addr, err));

                    if let Ok(packet) = result {
                        network
                            .send_to_peer(&peer_addr, packet.to_bytes())
                            .map_err(|err| warn!("Could not send packet to {}, reason: {:?}", peer_addr, err))
                            .unwrap_or(());
                    }
                } else {
                    debug!("No connections available! Fallback to bootstrap cache...");
                    
                    let peers_to_connect: Vec<SocketAddr> = network.bootstrap_cache
                        .entries()
                        .map(|e| e.to_socket_addr(network.port()))
                        .choose_multiple(&mut rand::thread_rng(), network.max_peers - peers.len());

                    for addr in peers_to_connect.iter() {
                        network
                            .connect(addr)
                            .map_err(|err| warn!("Could not connect to {}, reason: {:?}", addr, err))
                            .unwrap_or(());
                    }
                }
            } else if peers.len() == network.max_peers {
                debug!("We have enough peers. No need to refresh the peer list");
            } else {
                debug!("More peers than needed found! Disconnecting from {} peers.", peers.len() - network.max_peers);
                
                // TODO: Disconnect from the peers with the highest latency
                let iter = peers
                    .iter()
                    .filter_map(|(_, p)| p.id.as_ref())
                    .take(peers.len() - network.max_peers);

                for id in iter {
                    network
                        .disconnect(id)
                        .map_err(|err| warn!("Could not disconnect from peer with id {:?}! Reason: {:?}", id, err))
                        .unwrap_or(());
                }
            }

            ok(network)
        })
        .map_err(|err| warn!("Peer refresher error: {}", err))
        .and_then(|_| Ok(()));

    tokio::spawn(refresh_interval)
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_timeouts() {

//     }
// }
