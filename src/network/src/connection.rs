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

use tokio::io;
use tokio::net::{TcpStream, TcpListener};
use tokio::prelude::*;
use tokio_io_timeout::TimeoutStream;
use tokio::prelude::future::ok;
use network::Network;
use peer::Peer;
use packets::connect::Connect;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::BufReader;
use std::iter;
use parking_lot::Mutex;
use std::time::Duration;
use std::net::SocketAddr;
use tokio::executor::Spawn;

/// Purple network port
pub const PORT: u16 = 44034;
const PEER_TIMEOUT: u64 = 3000;

/// Initializes the listener for the given network 
pub fn start_listener(network: Arc<Mutex<Network>>, accept_connections: Arc<AtomicBool>, max_peers: usize) -> Spawn {
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
        .for_each(move |s| process_connection(network.clone(), s, max_peers, accept_connections.clone(), ConnectionType::Server));
    
    tokio::spawn(server)
}

pub fn connect_to_peer(network: Arc<Mutex<Network>>, accept_connections: Arc<AtomicBool>, max_peers: usize, addr: &SocketAddr) -> Spawn {
    let connect = TcpStream::connect(addr)
        .map_err(|e| warn!("connect failed = {:?}", e))
        .and_then(move |sock| process_connection(network, sock, max_peers, accept_connections, ConnectionType::Client));

    tokio::spawn(connect)
}

fn process_connection(
    network: Arc<Mutex<Network>>,
    sock: TcpStream,
    max_peers: usize,
    accept_connections: Arc<AtomicBool>,
    client_or_server: ConnectionType
) -> Spawn {
    let mut sock = TimeoutStream::new(sock);
            
    // Set timeout 
    sock.set_read_timeout(Some(Duration::from_millis(PEER_TIMEOUT)));
    sock.set_write_timeout(Some(Duration::from_millis(PEER_TIMEOUT)));

    let refuse_connection = Arc::new(AtomicBool::new(false));
    let addr = sock.get_ref().peer_addr().unwrap();

    match client_or_server {
        ConnectionType::Client => info!("Connecting to {}", addr),
        ConnectionType::Server => info!("Received connection request from {}", addr)
    };

    let network = network.clone();

    // Create new peer and add it to the peer table
    let peer = Peer::new(None, addr);
    network.lock().add_peer(peer);

    let peer_count = network.lock().peer_count();

    if peer_count >= max_peers {
        // Stop accepting peers
        accept_connections.store(false, Ordering::Relaxed);
    }

    // Split up the reading and writing parts of the
    // socket.
    let (reader, _writer) = sock.split();
    let reader = BufReader::new(reader);

    // Model the read portion of this socket by mapping an infinite
    // iterator to each line off the socket. This "loop" is then
    // terminated with an error once we hit EOF on the socket.
    let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));
    let network_clone = network.clone();
    let refuse_connection_clone = refuse_connection.clone();

    let socket_reader = iter
        .take_while(move |_| ok(!refuse_connection_clone.load(Ordering::Relaxed)))
        .fold(reader, move |reader, _| {
            let network = network_clone.clone();

            // Read a line off the socket, failing if we're at EOF.
            let line = io::read_until(reader, b'\n', Vec::new());
            let line = line.and_then(move |(reader, vec)| {
                if vec.len() == 0 {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
                } else {
                    Ok((reader, vec))
                }
            });

            let refuse_connection = refuse_connection.clone();
            
            line
                .map(move |(reader, message)| {
                    // We should receive a connect packet 
                    // if the peer's id is non-existent.
                    if network.lock().is_none_id(&addr) {
                        match Connect::from_bytes(&message) {
                            Ok(connect_packet) => {
                                debug!("Received connect packet from {}: {:?}", addr, connect_packet);
                                reader
                            },
                            _ => {
                                // Invalid packet, remove peer
                                debug!("Invalid connect packet from {}", addr);

                                // Flag socket for connection refusal
                                refuse_connection.store(true, Ordering::Relaxed);

                                reader
                            }
                        }
                    } else {
                        info!("{}: {}", addr, hex::encode(message));
                        reader   
                    }
                })
        });

    // Now that we've got futures representing each half of the socket, we
    // use the `select` combinator to wait for either half to be done to
    // tear down the other. Then we spawn off the result.
    let network = network.clone();
    let socket_reader = socket_reader.map_err(|_| ());

    let accept_connections = accept_connections.clone();

    // Spawn a task to process the connection
    tokio::spawn(socket_reader.then(move |_| {
        network.lock().remove_peer_with_addr(&addr);

        // Re-enable connections
        if network.lock().peer_count() < max_peers {
            accept_connections.store(true, Ordering::Relaxed);
        }

        info!("Connection to {} closed", addr);
        Ok(())
    }))
}

enum ConnectionType {
    Client,
    Server
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test] 
//     fn it_timeouts() {

//     }
// }