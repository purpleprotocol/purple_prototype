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

#[macro_use] extern crate log;
#[macro_use] extern crate unwrap;

extern crate crypto;
extern crate env_logger;
extern crate itc;
extern crate jump;
extern crate tokio;
extern crate parking_lot;
extern crate persistence;
extern crate kvdb;
extern crate kvdb_rocksdb;
extern crate clap;

use clap::{Arg, App};
use tokio::io::copy;
use tokio::net::TcpListener;
use tokio::prelude::*;
use parking_lot::RwLock;
use kvdb_rocksdb::{Database, DatabaseConfig};
use std::path::Path;
use std::env;

const PORT: u16 = 44034;
const NUM_OF_COLUMNS: u32 = 5;
const DEFAULT_NETWORK_NAME: &'static str = "purple-mainnet";

fn main() {
    env_logger::init();

    let argv = parse_cli_args();
    let _db_rw_lock: RwLock<Database> = RwLock::new(open_database(&argv.network_name)); 

    start_listener();
}

fn open_database(network_name: &str) -> Database {
    let config = DatabaseConfig::with_columns(Some(NUM_OF_COLUMNS));
    let path = Path::new(&env::home_dir().unwrap())
        .join("purple")
        .join(network_name)
        .join("db");

    Database::open(&config, path.to_str().unwrap()).unwrap()
}

fn start_listener() {
    info!("Starting TCP listener on port {}", PORT);

    // Bind the server's socket.
    let addr = format!("127.0.0.1:{}", PORT).parse().unwrap();
    let listener = TcpListener::bind(&addr).expect("unable to bind TCP listener");

    // Pull out a stream of sockets for incoming connections
    let server = listener
        .incoming()
        .map_err(|e| warn!("accept failed = {:?}", e))
        .for_each(|sock| {
            // Split up the reading and writing parts of the
            // socket.
            let (reader, writer) = sock.split();

            // A future that echos the data and returns how
            // many bytes were copied...
            let bytes_copied = copy(reader, writer);

            // ... after which we'll print what happened.
            let handle_conn = bytes_copied
                .map(|amt| debug!("wrote {:?} bytes", amt))
                .map_err(|err| warn!("IO error {:?}", err));

            // Spawn the future as a concurrent task.
            tokio::spawn(handle_conn)
        });
    
    // Start the Tokio runtime
    tokio::run(server);
}

struct Argv {
    network_name: String,
    mempool_size: u16,
}

fn parse_cli_args() -> Argv {
    let matches = App::new("purple")
        .arg(
            Arg::with_name("network_name")
                .long("network-name")
                .value_name("NETWORK_NAME")
                .help("The name of the network")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("mempool_size")
                .long("mempool-size")
                .value_name("MEMPOOL_SIZE")
                .help("The size in megabytes of the mempool")
                .takes_value(true)
        )
        .get_matches();

    let network_name: String = if let Some(arg) = matches.value_of("network_name") {
        unwrap!(
            arg.parse(),
            "Expected value for <NETWORK_NAME>"
        )
    } else {
        DEFAULT_NETWORK_NAME.to_owned()
    };

    let mempool_size: u16 = if let Some(arg) = matches.value_of("mempool_size") {
        unwrap!(
            arg.parse(),
            "Bad value for <MEMPOOL_SIZE>"
        )
    } else {
        150
    };
    
    Argv {
        network_name: network_name,
        mempool_size: mempool_size
    }
}