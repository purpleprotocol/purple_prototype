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

#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate jsonrpc_macros;

extern crate clap;
extern crate crypto;
extern crate dirs;
extern crate elastic_array;
extern crate env_logger;
extern crate futures;
extern crate hashdb;
extern crate itc;
extern crate jsonrpc_core;
extern crate jump;
extern crate kvdb;
extern crate kvdb_rocksdb;
extern crate network;
extern crate parking_lot;
extern crate persistence;
extern crate tokio;
extern crate chain;

use clap::{App, Arg};
use crypto::Identity;
use elastic_array::ElasticArray128;
use futures::future::ok;
use futures::Future;
use hashdb::HashDB;
use kvdb_rocksdb::{Database, DatabaseConfig};
use network::*;
use parking_lot::Mutex;
use persistence::PersistentDb;
use std::alloc::System;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

// Enforce usage of system allocator.
#[global_allocator]
static GLOBAL: System = System;

const NUM_OF_COLUMNS: u32 = 3;
const DEFAULT_NETWORK_NAME: &'static str = "purple";

fn main() {
    env_logger::init();

    let argv = parse_cli_args();
    let db = Arc::new(open_database(&argv.network_name));

    let mut node_storage = PersistentDb::new(db.clone(), Some(1));
    let ledger = PersistentDb::new(db, Some(2));

    let node_id = fetch_node_id(&mut node_storage);
    let network = Arc::new(Mutex::new(Network::new(
        node_id,
        argv.network_name.to_owned(),
    )));
    let accept_connections = Arc::new(AtomicBool::new(true));

    // Start the tokio runtime
    tokio::run(ok(()).and_then(move |_| {
        // Start listening to connections
        start_listener(network.clone(), accept_connections.clone(), argv.max_peers);

        // Start bootstrap process
        bootstrap(
            network,
            accept_connections,
            node_storage.clone(),
            argv.max_peers,
        );

        Ok(())
    }));
}

// Fetch stored node id or create new identity and store it
fn fetch_node_id(db: &mut PersistentDb) -> NodeId {
    let node_id_key = crypto::hash_slice(b"node_id");

    match db.get(&node_id_key) {
        Some(id) => {
            let mut buf = [0; 32];
            buf.copy_from_slice(&id);

            NodeId::new(buf)
        }
        None => {
            // Create new identity and write keys to database
            let identity = Identity::new();
            let node_skey_key = crypto::hash_slice(b"node_skey");

            let bin_pkey = identity.pkey().0;
            let bin_skey = identity.skey().0;

            db.emplace(node_id_key, ElasticArray128::<u8>::from_slice(&bin_pkey));
            db.emplace(node_skey_key, ElasticArray128::<u8>::from_slice(&bin_skey));

            NodeId::new(bin_pkey)
        }
    }
}

fn open_database(network_name: &str) -> Database {
    let config = DatabaseConfig::with_columns(Some(NUM_OF_COLUMNS));
    let path = Path::new(&dirs::home_dir().unwrap())
        .join("purple")
        .join(network_name)
        .join("db");

    Database::open(&config, path.to_str().unwrap()).unwrap()
}

struct Argv {
    network_name: String,
    mempool_size: u16,
    max_peers: usize,
}

fn parse_cli_args() -> Argv {
    let matches = App::new("purple")
        .arg(
            Arg::with_name("network_name")
                .long("network-name")
                .value_name("NETWORK_NAME")
                .help("The name of the network")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mempool_size")
                .long("mempool-size")
                .value_name("MEMPOOL_SIZE")
                .help("The size in megabytes of the mempool")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("max_peers")
                .long("max-peers")
                .value_name("MAX_PEERS")
                .help("The maximum number of allowed peer connections")
                .takes_value(true),
        )
        .get_matches();

    let network_name: String = if let Some(arg) = matches.value_of("network_name") {
        unwrap!(arg.parse(), "Expected value for <NETWORK_NAME>")
    } else {
        DEFAULT_NETWORK_NAME.to_owned()
    };

    let mempool_size: u16 = if let Some(arg) = matches.value_of("mempool_size") {
        unwrap!(arg.parse(), "Bad value for <MEMPOOL_SIZE>")
    } else {
        150
    };

    let max_peers: usize = if let Some(arg) = matches.value_of("max_peers") {
        unwrap!(arg.parse(), "Bad value for <MAX_PEERS>")
    } else {
        8
    };

    Argv {
        network_name: network_name,
        max_peers: max_peers,
        mempool_size: mempool_size,
    }
}
