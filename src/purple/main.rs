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

extern crate jump;
extern crate tokio;
extern crate itc;

use tokio::prelude::*;
use tokio::io::copy;
use tokio::net::TcpListener;

fn main() {
    // Bind the server's socket.
    let addr = "127.0.0.1:12345".parse().unwrap();
    let listener = TcpListener::bind(&addr)
        .expect("unable to bind TCP listener");

    // Pull out a stream of sockets for incoming connections
    let server = listener.incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(|sock| {
            // Split up the reading and writing parts of the
            // socket.
            let (reader, writer) = sock.split();

            // A future that echos the data and returns how
            // many bytes were copied...
            let bytes_copied = copy(reader, writer);

            // ... after which we'll print what happened.
            let handle_conn = bytes_copied.map(|amt| {
                println!("wrote {:?} bytes", amt)
            }).map_err(|err| {
                eprintln!("IO error {:?}", err)
            });

            // Spawn the future as a concurrent task.
            tokio::spawn(handle_conn)
        });

    // Start the Tokio runtime
    tokio::run(server);
}
