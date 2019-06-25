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

//extern crate mimalloc;
extern crate chain;
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
extern crate network;
extern crate parking_lot;
extern crate persistence;
extern crate tokio;
extern crate rocksdb;
extern crate common;

//use mimalloc::MiMalloc;
use common::checkpointable::DummyCheckpoint;
use rocksdb::{ColumnFamilyDescriptor, DB};
use clap::{App, Arg};
use crypto::{NodeId, Identity, SecretKey as Sk};
use elastic_array::ElasticArray128;
use futures::future::ok;
use futures::Future;
use hashdb::HashDB;
use network::*;
use parking_lot::{RwLock, Mutex};
use chain::*;
use persistence::PersistentDb;
use std::alloc::System;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::mpsc::channel;

// Use mimalloc allocator
// #[global_allocator]
// static GLOBAL: MiMalloc = MiMalloc;

// Enforce usage of system allocator.
#[global_allocator]
static GLOBAL: System = System;

const NUM_OF_COLUMNS: u32 = 3;
const DEFAULT_NETWORK_NAME: &'static str = "purple";
const COLUMN_FAMILIES: &'static [&'static str] = &[
    "state_chain",
    "easy_chain",
    "hard_chain",
    "node_storage",
];

fn main() {
    env_logger::init();
    
    info!("Opening databases...");

    let argv = parse_cli_args();
    let db = Arc::new(open_database(&argv.network_name));

    let mut node_storage = PersistentDb::new(db.clone(), Some(COLUMN_FAMILIES[3]));
    let state_db = PersistentDb::new(db.clone(), None);
    let state_chain_db = PersistentDb::new(db.clone(), Some(COLUMN_FAMILIES[0]));
    let easy_chain_db = PersistentDb::new(db.clone(), Some(COLUMN_FAMILIES[1]));
    let hard_chain_db = PersistentDb::new(db.clone(), Some(COLUMN_FAMILIES[2]));
    let easy_chain = Arc::new(RwLock::new(EasyChain::new(easy_chain_db, DummyCheckpoint::new(StorageLocation::Disk), argv.archival_mode)));
    let hard_chain = Arc::new(RwLock::new(HardChain::new(hard_chain_db, DummyCheckpoint::new(StorageLocation::Disk), argv.archival_mode)));
    let state_chain = Arc::new(RwLock::new(StateChain::new(state_chain_db, state_db, argv.archival_mode)));
    let easy_chain = EasyChainRef::new(easy_chain);
    let hard_chain = HardChainRef::new(hard_chain);
    let state_chain = StateChainRef::new(state_chain);
    let (easy_tx, easy_rx) = channel();
    let (hard_tx, hard_rx) = channel();
    let (state_tx, state_rx) = channel();

    info!("Setting up the network...");

    let (node_id, skey) = fetch_credentials(&mut node_storage);
    let network = Arc::new(Mutex::new(Network::new(
        node_id,
        argv.network_name.to_owned(),
        skey,
        argv.max_peers,
        easy_tx,
        hard_tx,
        state_tx,
        easy_chain.clone(),
        hard_chain.clone(),
        state_chain.clone()
    )));
    let accept_connections = Arc::new(AtomicBool::new(true));

    // Start the tokio runtime
    tokio::run(ok(()).and_then(move |_| {
        // Start listening for blocks
        start_block_listeners(network.clone(), easy_chain, hard_chain, state_chain, easy_rx, hard_rx, state_rx);

        // Start listening to connections
        start_listener(network.clone(), accept_connections.clone());

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
fn fetch_credentials(db: &mut PersistentDb) -> (NodeId, Sk) {
    let node_id_key = crypto::hash_slice(b"node_id");
    let node_skey_key = crypto::hash_slice(b"node_skey");

    match (db.get(&node_id_key), db.get(&node_skey_key)) {
        (Some(id), Some(skey)) => {
            let mut id_buf = [0; 32];
            let mut skey_buf = [0; 64];

            id_buf.copy_from_slice(&id);
            skey_buf.copy_from_slice(&skey);

            (NodeId::new(id_buf), Sk(skey_buf))
        }
        _ => {
            // Create new identity and write keys to database
            let identity = Identity::new();

            let bin_pkey = identity.pkey().0;
            let bin_skey = identity.skey().0;

            db.emplace(node_id_key, ElasticArray128::<u8>::from_slice(&bin_pkey));
            db.emplace(node_skey_key, ElasticArray128::<u8>::from_slice(&bin_skey));

           (NodeId::new(bin_pkey), identity.skey().clone())
        }
    }
}

// TODO: Add rocksdb config
fn open_database(network_name: &str) -> DB {
    let path = Path::new(&dirs::home_dir().unwrap())
        .join("purple")
        .join(network_name)
        .join("db");

    let mut cfs: Vec<ColumnFamilyDescriptor> = Vec::with_capacity(COLUMN_FAMILIES.len());

    for cf in COLUMN_FAMILIES {
        cfs.push(ColumnFamilyDescriptor::new(cf.to_owned(), persistence::cf_options()));
    }

    DB::open_cf_descriptors(&persistence::db_options(), path.to_str().unwrap(), cfs).unwrap()
}

struct Argv {
    network_name: String,
    mempool_size: u16,
    max_peers: usize,
    no_mempool: bool,
    interactive: bool,
    archival_mode: bool,
    mine_easy: bool,
    mine_hard: bool
}

fn parse_cli_args() -> Argv {
    let matches = App::new(format!("Purple Protocol v{}", env!("CARGO_PKG_VERSION")))
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
            Arg::with_name("no_mempool")
                .long("no-mempool")
                .conflicts_with("mempool_size")
                .help("Start the node without a mempool")
        )
        .arg(
            Arg::with_name("no_rpc")
                .long("no-rpc")
                .help("Start the node without the json-rpc interface")
        )
        .arg(
            Arg::with_name("interactive")
                .long("interactive")
                .short("i")
                .help("Start the node in interactive mode")
        )
        .arg(
            Arg::with_name("mine_easy")
                .long("mine-easy")
                .conflicts_with("mine_hard")
                .help("Start mining on the Easy Chain")
        )
        .arg(
            Arg::with_name("mine_hard")
                .long("mine-hard")
                .help("Start mining on the Hard Chain")
        )
        .arg(
            Arg::with_name("max_peers")
                .long("max-peers")
                .value_name("MAX_PEERS")
                .help("The maximum number of allowed peer connections. Default is 8")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("prune")
                .long("prune")
                .help("Whether to prune the ledger or to keep the entire transaction history. False by default."),
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

    let archival_mode: bool = !matches.is_present("prune");
    let mine_easy: bool = matches.is_present("mine_easy");
    let mine_hard: bool = matches.is_present("mine_hard");
    let no_mempool: bool = matches.is_present("no_mempool");
    let interactive: bool = matches.is_present("interactive");

    Argv {
        network_name,
        mine_easy,
        mine_hard,
        max_peers,
        no_mempool,
        interactive,
        mempool_size,
        archival_mode,
    }
}
