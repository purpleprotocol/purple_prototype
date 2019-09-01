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
use crate::interface::NetworkInterface;
use crate::network::Network;
use crate::packet::Packet;
use crate::packets::connect::Connect;
use crate::peer::{ConnectionType, Peer};
use parking_lot::Mutex;
use std::io::BufReader;
use std::iter;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::executor::Spawn;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::future::ok;
use tokio::prelude::*;
use tokio_io_timeout::TimeoutStream;

/// Purple network port
pub const PORT: u16 = 44034;
const PEER_TIMEOUT: u64 = 3000;

/// Initializes the listener for the given network
pub fn start_listener(network: Arc<Mutex<Network>>, accept_connections: Arc<AtomicBool>) -> Spawn {
    info!("Starting TCP listener on port {}", PORT);

    // Bind the server's socket.
    let addr = format!("127.0.0.1:{}", PORT).parse().unwrap();
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
    network: Arc<Mutex<Network>>,
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
    network: Arc<Mutex<Network>>,
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

    let network = network.clone();

    // Create new peer and add it to the peer table
    let peer = Peer::new(None, addr, client_or_server);

    let (node_id, skey) = {
        let mut network = network.lock();

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

    // Model the read portion of this socket by mapping an infinite
    // iterator to each line off the socket. This "loop" is then
    // terminated with an error once we hit EOF on the socket.
    let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));
    let network_clone = network.clone();
    let network_clone2 = network.clone();
    let network = network_clone.clone();
    let refuse_connection_clone = refuse_connection.clone();

    let writer_iter = stream::iter_ok::<_, ()>(iter::repeat(()));
    let socket_writer = writer_iter.fold(writer, move |mut writer, _| {
        let mut network = network_clone.lock();
        let peer = network.peers.get_mut(&addr).unwrap();

        // Write a connect packet if we are the client
        // and we have not yet sent a connect packet.
        if let ConnectionType::Client = client_or_server {
            if !peer.sent_connect {
                // Send `Connect` packet.
                let mut connect = Connect::new(node_id.clone(), peer.pk);
                connect.sign(&skey);

                let packet = connect.to_bytes();

                writer
                    .poll_write(&packet)
                    .map_err(|err| warn!("write failed = {:?}", err))
                    .and_then(|_| Ok(()))
                    .unwrap();

                peer.sent_connect = true;
            }
        }

        // Pop packet from outbound buffer and write it to the socket.
        if let Some(packet) = peer.outbound_buffer.pop_back() {
            writer
                .poll_write(&packet)
                .map_err(|err| warn!("write failed = {:?}", err))
                .and_then(|_| Ok(()))
                .unwrap();
        }

        ok(writer)
    });

    let socket_reader = iter
        .take_while(move |_| ok(!refuse_connection_clone.load(Ordering::Relaxed)))
        .fold(reader, move |reader, _| {
            let network = network.clone();

            // Read a line off the socket, failing if we're at EOF.
            let line = io::read_until(reader, b'\n', Vec::new());
            let line = line.and_then(move |(reader, vec)| {
                if vec.len() == 0 {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
                } else {
                    Ok((reader, vec))
                }
            });

            let network_clone = network.clone();
            let refuse_connection = refuse_connection.clone();

            line.map(move |(reader, message)| {
                let result = network.lock().process_packet(&addr, &message);
                (reader, result)
            })
            .map(move |(reader, result)| {
                // TODO: Handle other errors as well
                if let Err(NetworkErr::InvalidConnectPacket) = result {
                    let network = network_clone.clone();

                    // Flag socket for connection refusal if we
                    // have received an invalid connect packet.
                    refuse_connection.store(true, Ordering::Relaxed);

                    // Also, ban the peer
                    network.lock().ban_ip(&addr).unwrap();
                }

                reader
            })
        });

    // Now that we've got futures representing each half of the socket, we
    // use the `select` combinator to wait for either half to be done to
    // tear down the other. Then we spawn off the result.
    let network = network_clone2.clone();
    let socket_reader = socket_reader.map_err(|_| ());
    let socket_writer = socket_writer.map_err(|_| ());

    let accept_connections = accept_connections.clone();

    // Spawn task to process socket writing
    tokio::spawn(socket_writer.then(move |_| {
        debug!("Write half of {} closed", addr);
        Ok(())
    }));

    // Spawn a task to process the connection
    tokio::spawn(socket_reader.then(move |_| {
        let mut network = network.lock();
        network.remove_peer_with_addr(&addr);

        // Re-enable connections
        if network.peer_count() < network.max_peers {
            accept_connections.store(true, Ordering::Relaxed);
        }

        info!("Connection to {} closed", addr);
        Ok(())
    }))
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_timeouts() {

//     }
// }
